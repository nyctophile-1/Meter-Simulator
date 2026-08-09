namespace ManyMeterSimulator.BadComm;

/// <summary>How a meter behaves on the wire.</summary>
public enum CommClass
{
    /// <summary>Normal: global network delay only.</summary>
    Healthy = 0,

    /// <summary>Slow and lossy: multiplied latency plus a per-exchange drop chance.</summary>
    BadComm = 1,

    /// <summary>Never answers. Requests are swallowed; the HES times out and retries.</summary>
    NonComm = 2,
}

/// <summary>What a manual rule selects meters by. All matchers are integer predicates over the
/// meter index - serial and index are the same number, so no string matching reaches the hot
/// path.</summary>
public enum MatchKind
{
    /// <summary>Inclusive index range.</summary>
    Range = 0,

    /// <summary>index % Modulus == Remainder. Expresses "every Nth meter" / digit-suffix rules.</summary>
    Modulo = 1,

    /// <summary>Explicit list of indices.</summary>
    List = 2,
}

/// <summary>The BadComm section of the runtime config. Persisted; see MayaRuntimeConfig.</summary>
public sealed class BadCommConfig
{
    /// <summary>Master switch. When false every meter is healthy, whatever the rules say.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Changing this reshuffles which meters are impaired without changing the percentages -
    /// useful for re-running a test against a different population.
    /// </summary>
    public int Seed { get; set; } = 1;

    public AutoAllocation Auto { get; set; } = new();

    public BadCommDefaults Defaults { get; set; } = new();

    public List<BadCommRule> Rules { get; set; } = new();
}

/// <summary>Percentage of the fleet auto-assigned to each impaired class.</summary>
public sealed class AutoAllocation
{
    /// <summary>Share that never answers.</summary>
    public double NonCommPercent { get; set; } = 0.1;

    /// <summary>Share that is slow and lossy.</summary>
    public double BadCommPercent { get; set; } = 5.0;
}

/// <summary>Applied to auto-allocated bad-comm meters, and used as the seed values for new rules.</summary>
public sealed class BadCommDefaults
{
    /// <summary>Chance that any single exchange is dropped. 100 makes the meter effectively non-comm.</summary>
    public double FailureRatePercent { get; set; } = 5.0;

    /// <summary>
    /// Latency multiplier, drawn once per meter and then fixed, so a bad meter is consistently
    /// bad. Min == Max means every bad-comm meter is equally slow.
    /// </summary>
    public int MultiplierMin { get; set; } = 25;

    public int MultiplierMax { get; set; } = 25;
}

/// <summary>An operator-defined override. Rules are evaluated before auto allocation.</summary>
public sealed class BadCommRule
{
    public int Id { get; set; }

    public string Name { get; set; } = "";

    public bool Enabled { get; set; } = true;

    /// <summary>Lower runs first; the first match wins.</summary>
    public int Order { get; set; }

    public MatchKind Match { get; set; } = MatchKind.Range;

    public long From { get; set; }

    public long To { get; set; }

    public long Modulus { get; set; } = 1;

    public long Remainder { get; set; }

    public List<long> Indices { get; set; } = new();

    /// <summary>What matched meters become. Healthy exists to carve a known-good meter out of an
    /// auto band - without it there would be no way to exempt a demo meter.</summary>
    public CommClass Effect { get; set; } = CommClass.BadComm;

    /// <summary>Only meaningful when <see cref="Effect"/> is BadComm.</summary>
    public double FailureRatePercent { get; set; } = 5.0;

    public int MultiplierMin { get; set; } = 25;

    public int MultiplierMax { get; set; } = 25;
}
