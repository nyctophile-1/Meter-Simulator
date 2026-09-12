namespace ManyMeterSimulator.ProfileSimulation;

/// <summary>
/// Explicitly configured profile simulation. It is disabled by default: a template describes
/// layout and seed values, but it does not by itself establish how every captured field should
/// change or how a receiver expects that profile to be pushed.
/// </summary>
public sealed class ProfileSimulationOptions
{
    public const string SectionName = "ProfileSimulation";

    /// <summary>Enables working XML creation and the bounded background scheduler.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Persistent state root. Relative paths resolve against the app content root so the default
    /// remains outside a redeployed application directory, alongside other durable app data.
    /// </summary>
    public string StateFolder { get; set; } = "../data/profile-simulation";

    /// <summary>Windows or IANA timezone id used to align completed capture boundaries.</summary>
    public string TimeZoneId { get; set; } = "UTC";

    /// <summary>How often the scheduler checks for due captures.</summary>
    public int SchedulerIntervalSeconds { get; set; } = 15;

    /// <summary>
    /// Bounds work per running batch on one scheduler pass. A large fleet is processed round-robin
    /// over successive passes rather than allocating a permanent timer or an unbounded task per meter.
    /// </summary>
    public int MaxMetersPerBatchPerCycle { get; set; } = 100;

    /// <summary>Bounds restart catch-up work for one meter/profile on one scheduler pass.</summary>
    public int MaxCapturesPerMeterPerCycle { get; set; } = 16;

    /// <summary>Profiles to advance. Empty means no data is generated even when enabled.</summary>
    public List<ProfileSimulationProfile> Profiles { get; set; } = new();
}

/// <summary>One explicitly approved profile capture rule.</summary>
public sealed class ProfileSimulationProfile
{
    /// <summary>ProfileGeneric logical name from the uploaded/template XML.</summary>
    public string LogicalName { get; set; } = string.Empty;

    /// <summary>
    /// Optional explicit capture period. Zero adopts a positive CapturePeriod from the XML; it is
    /// rejected for profiles such as billing/events whose XML period is zero until a calendar rule
    /// has been configured and implemented.
    /// </summary>
    public int CapturePeriodSeconds { get; set; }

    /// <summary>
    /// Explicit numeric changes keyed by the captured object's logical name. Unlisted columns copy
    /// their latest saved value, which avoids assigning electrical semantics to unknown fields.
    /// </summary>
    public List<ProfileValueIncrement> ValueIncrements { get; set; } = new();
}

/// <summary>An explicitly configured numeric increment for one captured object.</summary>
public sealed class ProfileValueIncrement
{
    public string CaptureObjectLogicalName { get; set; } = string.Empty;

    public decimal IncrementPerCapture { get; set; }
}
