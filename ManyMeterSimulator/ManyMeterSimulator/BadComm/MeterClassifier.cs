namespace ManyMeterSimulator.BadComm;

/// <summary>What the NIC needs to know about one meter, resolved once and cached per connection.</summary>
public readonly record struct MeterImpairment(
    CommClass Class,
    double FailureRatePercent,
    int Multiplier,
    string Reason)
{
    public static readonly MeterImpairment Healthy =
        new(CommClass.Healthy, 0, 1, "healthy");
}

/// <summary>
/// Decides how a meter behaves on the wire, from its index alone.
///
/// Assignment is COMPUTED, never stored. A million meters rules out a per-meter flag, and
/// "stays impaired across restarts" rules out anything random at runtime. A pure function of the
/// index gives both, plus retroactivity for free: change a percentage and the whole fleet
/// reclassifies with nothing to migrate.
///
/// The two auto bands share ONE hash with cumulative thresholds, which makes membership nested:
/// a meter is non-comm iff h &lt; nm, so raising nm only ever ADDS meters and never releases one
/// that was already impaired. Two independent hashes would break that guarantee.
///
/// Immutable once built. Config changes construct a new instance and swap it behind a volatile
/// reference, so the hot path never locks and never sees a half-applied change.
/// </summary>
public sealed class MeterClassifier
{
    private const uint Ppm = 1_000_000;   // parts per million: 0.0001% granularity

    // Distinct salts keep band selection and severity uncorrelated.
    private const ulong BandSalt = 0x1;
    private const ulong SeveritySalt = 0x2;

    private readonly bool _enabled;
    private readonly ulong _seed;
    private readonly uint _nonCommPpm;
    private readonly uint _badCommCeilingPpm;   // cumulative: nonComm + badComm
    private readonly BadCommDefaults _defaults;
    private readonly BadCommRule[] _rules;      // pre-sorted, enabled only

    /// <summary>
    /// Bumped on every rebuild. Connections cache their classification alongside this number and
    /// re-resolve when it changes, which is what makes a config edit apply to already-open
    /// sessions without a reconnect.
    /// </summary>
    public int Generation { get; }

    public MeterClassifier(BadCommConfig config, int generation)
    {
        Generation = generation;
        _enabled = config.Enabled;
        _seed = (ulong)config.Seed;
        _defaults = config.Defaults;

        _nonCommPpm = ToPpm(config.Auto.NonCommPercent);
        // Clamped so a nonsensical pair (e.g. 80% + 80%) cannot wrap past the full range.
        _badCommCeilingPpm = (uint)Math.Min(Ppm, (long)_nonCommPpm + ToPpm(config.Auto.BadCommPercent));

        _rules = config.Rules
            .Where(r => r.Enabled)
            .OrderBy(r => r.Order)
            .ThenBy(r => r.Id)
            .ToArray();
    }

    /// <summary>An all-healthy classifier, used before any config has been loaded.</summary>
    public static MeterClassifier Disabled { get; } = new(new BadCommConfig { Enabled = false }, 0);

    public MeterImpairment Classify(long index)
    {
        if (!_enabled)
        {
            return MeterImpairment.Healthy;
        }

        // Manual rules beat auto allocation: an operator singling out a meter has made a more
        // specific decision than a percentage band.
        foreach (BadCommRule rule in _rules)
        {
            if (!Matches(rule, index))
            {
                continue;
            }

            return rule.Effect switch
            {
                CommClass.NonComm => new MeterImpairment(CommClass.NonComm, 100, 1, $"rule #{rule.Id} {rule.Name}"),
                CommClass.Healthy => new MeterImpairment(CommClass.Healthy, 0, 1, $"rule #{rule.Id} {rule.Name}"),
                _ => new MeterImpairment(
                    CommClass.BadComm,
                    rule.FailureRatePercent,
                    DrawMultiplier(index, rule.MultiplierMin, rule.MultiplierMax),
                    $"rule #{rule.Id} {rule.Name}"),
            };
        }

        uint h = StableHash.ToRange(StableHash.Mix(BandSalt ^ _seed, (ulong)index), Ppm);

        if (h < _nonCommPpm)
        {
            return new MeterImpairment(CommClass.NonComm, 100, 1, $"auto non-comm (h={h} ppm)");
        }

        if (h < _badCommCeilingPpm)
        {
            return new MeterImpairment(
                CommClass.BadComm,
                _defaults.FailureRatePercent,
                DrawMultiplier(index, _defaults.MultiplierMin, _defaults.MultiplierMax),
                $"auto bad-comm (h={h} ppm)");
        }

        return MeterImpairment.Healthy with { Reason = $"auto healthy (h={h} ppm)" };
    }

    /// <summary>
    /// Severity is drawn once per meter and then fixed forever, so a bad meter is CONSISTENTLY
    /// bad rather than randomly slow. Per-exchange jitter comes from the network-delay draw, not
    /// from here.
    /// </summary>
    private int DrawMultiplier(long index, int min, int max)
    {
        int lo = Networking.DelayLimits.ClampMultiplier(min);
        int hi = Networking.DelayLimits.ClampMultiplier(Math.Max(min, max));
        if (lo >= hi)
        {
            return lo;
        }

        uint span = (uint)(hi - lo + 1);
        return lo + (int)StableHash.ToRange(StableHash.Mix(SeveritySalt ^ _seed, (ulong)index), span);
    }

    private static bool Matches(BadCommRule rule, long index) => rule.Match switch
    {
        MatchKind.Range => index >= rule.From && index <= rule.To,
        MatchKind.Modulo => rule.Modulus > 0 && index % rule.Modulus == rule.Remainder,
        MatchKind.List => rule.Indices.Contains(index),
        _ => false,
    };

    private static uint ToPpm(double percent) =>
        (uint)Math.Clamp(Math.Round(percent * 10_000), 0, Ppm);
}
