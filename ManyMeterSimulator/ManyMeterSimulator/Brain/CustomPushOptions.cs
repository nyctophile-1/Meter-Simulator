namespace ManyMeterSimulator.Brain;

/// <summary>Wirepas envelope settings for custom scheduled pushes.</summary>
public sealed class CustomPushOptions
{
    public const string SectionName = "CustomPush";

    public string WirepasGatewayId { get; set; } = "sim-gw";
    public string WirepasSinkId { get; set; } = "sink1";
    public uint WirepasEndpoint { get; set; } = 10;
}
