namespace ManyMeterSimulator.Networking;

/// <summary>
/// Startup defaults for the artificial per-exchange delay. Only seeds
/// <see cref="NetworkDelaySettings"/>; the live values are changed from the Setup page at
/// runtime and are NOT written back here, so a restart returns to these numbers.
/// </summary>
public class NetworkDelayOptions
{
    public const string SectionName = "NetworkDelay";

    /// <summary>Lower bound in milliseconds. 0 = no delay (the original behaviour).</summary>
    public int LowerMs { get; set; }

    /// <summary>Upper bound in milliseconds, inclusive. Must be >= <see cref="LowerMs"/>.</summary>
    public int UpperMs { get; set; }
}
