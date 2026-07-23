namespace ManyMeterSimulator.Brain;

/// <summary>
/// Settings for the in-process DLMS brain. Bound from the "Brain" config section.
/// </summary>
public sealed class BrainOptions
{
    public const string SectionName = "Brain";

    /// <summary>DLMS client (HES) address the meter expects. Fixed across meters.</summary>
    public int ClientAddress { get; set; } = 16;

    /// <summary>
    /// DLMS server (lower/logical device) address. Fixed across meters — routing to the right
    /// meter is by IPv6, and the session accepts whatever the HES dials (see DLMSServerSession.IsTarget).
    /// </summary>
    public int ServerAddress { get; set; } = 1;

    /// <summary>Meter logical name passed to DLMSMeter (informational).</summary>
    public string LogicalName { get; set; } = "1.0.0.0.0.255";

    /// <summary>
    /// Which <c>IMeterSimBridge</c> to use: "Brain" (real DLMS engine, default) or
    /// "Simulated" (echo stand-in that exercises framing only).
    /// </summary>
    public string Mode { get; set; } = "Brain";
}
