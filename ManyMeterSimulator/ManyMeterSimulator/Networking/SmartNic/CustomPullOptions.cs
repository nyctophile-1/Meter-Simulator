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
}
