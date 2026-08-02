using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Settings;

namespace ManyMeterSimulator.BadComm;

/// <summary>
/// Owns the live <see cref="MeterClassifier"/> and persists operator changes.
///
/// Same shape as <see cref="NetworkDelaySettings"/>: an immutable snapshot behind a volatile
/// reference, so the hot path reads without locking and can never observe a half-applied config.
/// Writes go through the runtime config store, so impairment settings survive restart and
/// redeploy exactly like batches do.
/// </summary>
public sealed class BadCommSettings
{
    private readonly IRuntimeConfigStore _store;
    private readonly object _writeLock = new();

    private volatile MeterClassifier _classifier;
    private BadCommConfig _config;
    private int _generation;

    public BadCommSettings(IRuntimeConfigStore store)
    {
        _store = store;

        // Missing section (an older config file) deserializes to null and means "defaults".
        _config = store.Current.BadComm ?? new BadCommConfig();
        _generation = 1;
        _classifier = new MeterClassifier(_config, _generation);
    }

    /// <summary>The current compiled classifier. Cheap to read; capture once per exchange.</summary>
    public MeterClassifier Classifier => _classifier;

    /// <summary>A copy of the live config, for the UI to edit without touching the running one.</summary>
    public BadCommConfig Snapshot() => Clone(_config);

    /// <summary>
    /// Replaces the whole section, rebuilds the classifier and persists. Returns false with a
    /// reason if the config is invalid.
    /// </summary>
    public bool TryUpdate(BadCommConfig updated, out string? error)
    {
        error = Validate(updated);
        if (error is not null)
        {
            return false;
        }

        lock (_writeLock)
        {
            BadCommConfig copy = Clone(updated);
            _config = copy;
            // New generation forces open connections to re-resolve on their next exchange, which
            // is what makes a change retroactive rather than applying only to new sessions.
            _classifier = new MeterClassifier(copy, ++_generation);
            _store.Update(doc => doc.BadComm = copy);
        }

        return true;
    }

    private static string? Validate(BadCommConfig c)
    {
        if (c.Auto.NonCommPercent < 0 || c.Auto.BadCommPercent < 0)
        {
            return "Percentages cannot be negative.";
        }

        if (c.Auto.NonCommPercent + c.Auto.BadCommPercent > 100)
        {
            return "Non-comm and bad-comm together cannot exceed 100% of the fleet.";
        }

        if (c.Defaults.FailureRatePercent is < 0 or > 100)
        {
            return "Failure rate must be between 0 and 100%.";
        }

        if (!IsMultiplierPairValid(c.Defaults.MultiplierMin, c.Defaults.MultiplierMax))
        {
            return $"Multiplier must be between 1 and {DelayLimits.MaxMultiplier}, and max cannot be below min.";
        }

        foreach (BadCommRule r in c.Rules)
        {
            if (string.IsNullOrWhiteSpace(r.Name))
            {
                return "Every rule needs a name.";
            }

            if (r.Match == MatchKind.Range && r.To < r.From)
            {
                return $"Rule '{r.Name}': range end cannot be before the start.";
            }

            if (r.Match == MatchKind.Modulo && r.Modulus < 1)
            {
                return $"Rule '{r.Name}': modulus must be at least 1.";
            }

            if (r.Match == MatchKind.List && r.Indices.Count == 0)
            {
                return $"Rule '{r.Name}': the list is empty.";
            }

            if (r.Effect == CommClass.BadComm)
            {
                if (r.FailureRatePercent is < 0 or > 100)
                {
                    return $"Rule '{r.Name}': failure rate must be between 0 and 100%.";
                }

                if (!IsMultiplierPairValid(r.MultiplierMin, r.MultiplierMax))
                {
                    return $"Rule '{r.Name}': multiplier must be 1-{DelayLimits.MaxMultiplier}, max not below min.";
                }
            }
        }

        return null;
    }

    private static bool IsMultiplierPairValid(int min, int max) =>
        min >= 1 && max >= min && max <= DelayLimits.MaxMultiplier;

    /// <summary>
    /// Deep copy so the UI's working object and the persisted document can never alias the live
    /// config - an in-place edit would otherwise take effect before Apply was pressed.
    /// </summary>
    private static BadCommConfig Clone(BadCommConfig c) => new()
    {
        Enabled = c.Enabled,
        Seed = c.Seed,
        Auto = new AutoAllocation
        {
            NonCommPercent = c.Auto.NonCommPercent,
            BadCommPercent = c.Auto.BadCommPercent,
        },
        Defaults = new BadCommDefaults
        {
            FailureRatePercent = c.Defaults.FailureRatePercent,
            MultiplierMin = c.Defaults.MultiplierMin,
            MultiplierMax = c.Defaults.MultiplierMax,
        },
        Rules = c.Rules.Select(r => new BadCommRule
        {
            Id = r.Id,
            Name = r.Name,
            Enabled = r.Enabled,
            Order = r.Order,
            Match = r.Match,
            From = r.From,
            To = r.To,
            Modulus = r.Modulus,
            Remainder = r.Remainder,
            Indices = new List<long>(r.Indices),
            Effect = r.Effect,
            FailureRatePercent = r.FailureRatePercent,
            MultiplierMin = r.MultiplierMin,
            MultiplierMax = r.MultiplierMax,
        }).ToList(),
    };
}
