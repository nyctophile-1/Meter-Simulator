namespace ManyMeterSimulator.Brain;

/// <summary>Wirepas envelope settings for custom scheduled pushes.</summary>
public sealed class CustomPushOptions
{
    public const string SectionName = "CustomPush";

    public string WirepasGatewayId { get; set; } = "sim-gw";
    public string WirepasSinkId { get; set; } = "sink1";
    public uint WirepasEndpoint { get; set; } = 10;
    public Dictionary<int, string> MeterCategories { get; set; } = new();
    public Dictionary<int, uint> ResponseMagicNumbers { get; set; } = new();
    public int ResponseTimestampOffsetMinutes { get; set; } = 330;
    public int[]? EventsWithPowerProfile { get; set; }
    public Dictionary<int, Dictionary<string, int>> EventIds { get; set; } = new();
}
