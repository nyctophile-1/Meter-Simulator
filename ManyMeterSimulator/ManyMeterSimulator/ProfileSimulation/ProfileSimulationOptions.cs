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
    /// Bounds restart catch-up work for one batch/profile on one scheduler pass. Generation is
    /// per-batch (not per-meter — see BatchProfileSimulationState), so this bounds how many missed
    /// boundaries one profile can catch up on in a single tick, not how many meters are touched.
    /// </summary>
    public int MaxCapturesPerCycle { get; set; } = 16;

    /// <summary>
    /// A batch's shared working-state folder (model.xml + previous snapshot + metadata) is deleted
    /// once nothing has written to it for this many days. Nothing previously bounded how many such
    /// folders accumulate as batches are created, retired, or the feature is toggled off and on —
    /// that gap is what let an earlier (per-meter) build's state folder grow to ~20,000 orphaned
    /// files in production.
    /// </summary>
    public int StateRetentionDays { get; set; } = 45;

    /// <summary>Profiles to advance. Empty means no data is generated even when enabled.</summary>
    public List<ProfileSimulationProfile> Profiles { get; set; } = new();
}

/// <summary>
/// How a profile's next capture boundary is computed. <see cref="FixedPeriod"/> is the original
/// (and only previously implemented) rule; <see cref="DailyMidnight"/> and <see cref="MonthlyFirst"/>
/// add the calendar-based boundaries DP and Billing actually use instead of a numeric period.
/// <see cref="Instantaneous"/> has no buffer/history at all — it updates current scalar values
/// directly on the same cadence, since IP is "the value right now", not a retained record.
/// </summary>
public enum ProfileCaptureRule
{
    FixedPeriod,
    DailyMidnight,
    MonthlyFirst,
    Instantaneous,
}

/// <summary>One explicitly approved profile capture rule.</summary>
public sealed class ProfileSimulationProfile
{
    /// <summary>
    /// For <see cref="ProfileCaptureRule.FixedPeriod"/>/<see cref="ProfileCaptureRule.DailyMidnight"/>/
    /// <see cref="ProfileCaptureRule.MonthlyFirst"/>: the ProfileGeneric logical name from the
    /// template. For <see cref="ProfileCaptureRule.Instantaneous"/>: the instantaneous PushSetup's
    /// logical name (e.g. "0.0.25.9.0.255") — IP is identified by its push setup's object list
    /// everywhere else in this codebase (see MeterDataSnapshotReader), so simulation reuses the
    /// same identity rather than inventing a second one.
    /// </summary>
    public string LogicalName { get; set; } = string.Empty;

    /// <summary>Which boundary rule this profile advances on. Defaults to the original fixed-period behavior.</summary>
    public ProfileCaptureRule CaptureRule { get; set; } = ProfileCaptureRule.FixedPeriod;

    /// <summary>
    /// Optional explicit capture period, used only when <see cref="CaptureRule"/> is
    /// <see cref="ProfileCaptureRule.FixedPeriod"/>. Zero adopts a positive CapturePeriod from the
    /// XML.
    /// </summary>
    public int CapturePeriodSeconds { get; set; }

    /// <summary>
    /// Explicit numeric changes keyed by the captured object's logical name. Unlisted columns copy
    /// their latest saved value, which avoids assigning electrical semantics to unknown fields.
    /// </summary>
    public List<ProfileValueIncrement> ValueIncrements { get; set; } = new();

    /// <summary>
    /// Whether a newly generated record for this profile is immediately queued for push. Forced to
    /// false for <see cref="ProfileCaptureRule.Instantaneous"/> — IP data can only be sent via the
    /// operator's manual "Send Push Now" action, never automatically, until randomized/live-feeling
    /// IP generation is designed.
    /// </summary>
    public bool AutoPush { get; set; } = true;

    /// <summary>
    /// The PushSetup's own logical name to auto-push through when <see cref="AutoPush"/> is true —
    /// required in that case. This is deliberately a SEPARATE value from <see cref="LogicalName"/>:
    /// a profile's own identity (e.g. Daily's "1.0.99.2.0.255") and the OBIS the HES dispatches its
    /// push on (Daily's "0.6.25.9.0.255") are different numbers for every profile type, including
    /// Block Load ("1.0.99.1.0.255" vs. "0.5.25.9.0.255"). Passing the profile's own LogicalName to
    /// PushCoordinator here would silently find no matching PushSetup and push nothing.
    /// </summary>
    public string? AutoPushSetupLogicalName { get; set; }
}

/// <summary>An explicitly configured numeric increment for one captured object.</summary>
public sealed class ProfileValueIncrement
{
    public string CaptureObjectLogicalName { get; set; } = string.Empty;

    public decimal IncrementPerCapture { get; set; }
}
