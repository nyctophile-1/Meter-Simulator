namespace ManyMeterSimulator.Settings;

/// <summary>
/// Everything an operator can change at runtime from the UI and expect to survive a restart,
/// held as one versioned document with a named section per feature.
///
/// Deliberately separate from the batch store: batches are fleet identity (losing them reissues
/// addresses the HES already knows), whereas these are behavioural knobs where falling back to
/// the configured default is harmless. The two have different corruption policies as a result -
/// see <see cref="JsonRuntimeConfigStore"/>.
///
/// To add a setting: add a section property here and read/write it through
/// <see cref="IRuntimeConfigStore.Update"/>. Old files stay readable because a missing section
/// deserializes to null, which each consumer treats as "use the configured default".
/// </summary>
public sealed class MayaRuntimeConfig
{
    /// <summary>Bumped only if a future change needs migration logic; unread today.</summary>
    public int Version { get; set; } = 1;

    /// <summary>Simulated wire time applied before the request reaches the brain.</summary>
    public DelayRange? NetworkDelay { get; set; }

    // Future sections slot in here, e.g. a BridgeDelay to mimic slow meters:
    //     public DelayRange? BridgeDelay { get; set; }
}

/// <summary>An inclusive millisecond range. Shared shape so every future delay knob looks alike.</summary>
public sealed class DelayRange
{
    public int LowerMs { get; set; }

    public int UpperMs { get; set; }
}
