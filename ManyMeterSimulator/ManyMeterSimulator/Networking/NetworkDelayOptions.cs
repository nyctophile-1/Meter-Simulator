namespace ManyMeterSimulator.Networking;

/// <summary>
/// Startup defaults for the artificial per-exchange delay. Only seeds
/// <see cref="NetworkDelaySettings"/>; the live values are changed from the Setup page at
/// runtime and are NOT written back here, so a restart returns to these numbers.
/// </summary>
public class NetworkDelayOptions
{
    public const string SectionName = "NetworkDelay";

    /// <summary>
    /// Lower bound in milliseconds. Defaults to 100 so a fresh deployment already behaves like a
    /// real field link rather than answering instantly; set both bounds to 0 to disable.
    /// </summary>
    public int LowerMs { get; set; } = 100;

    /// <summary>
    /// Upper bound in milliseconds, inclusive. Must be >= <see cref="LowerMs"/> and no more than
    /// <see cref="DelayLimits.MaxNetworkDelayMs"/>. 100-300 gives a ~200 ms mean round trip.
    /// </summary>
    public int UpperMs { get; set; } = 300;
}
