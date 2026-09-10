namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>Location of the read-only CSV export that describes HES custom-pull templates.</summary>
public sealed class CustomPullOptions
{
    public const string SectionName = "CustomPull";

    /// <summary>
    /// Relative paths are resolved against the application content root. The export is intentionally
    /// optional: its absence disables only the custom endpoint, never normal DLMS traffic.
    /// </summary>
    public string DataModelDirectory { get; set; } = "KimbalSpecifics/DataModel";

    /// <summary>Explicit response magic for templates with several registered HES mappings.</summary>
    public Dictionary<int, uint> ResponseMagicNumbers { get; set; } = new();
    public Dictionary<int, string> MeterCategories { get; set; } = new();
    /// <summary>DataModel generates simulated rows; Meter reads only the existing XML-backed meter.</summary>
    public string ProfileDataSource { get; set; } = "DataModel";
    public int MaxProfileRows { get; set; } = 4096;
    public int MaxDlmsBlocks { get; set; } = 4096;
    public int MaxResponseBytes { get; set; } = 4 * 1024 * 1024;
    public int ReadTimeoutSeconds { get; set; } = 30;
    public int BlockRequestOffsetMinutes { get; set; } = 330;
    public int ResponseTimestampOffsetMinutes { get; set; } = 330;
    public int[]? EventsWithPowerProfile { get; set; }
}
