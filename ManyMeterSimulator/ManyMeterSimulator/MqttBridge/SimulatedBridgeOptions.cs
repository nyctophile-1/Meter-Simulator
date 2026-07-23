namespace ManyMeterSimulator.MqttBridge;

public class SimulatedBridgeOptions
{
    public const string SectionName = "SimulatedBridge";

    public int RoundTripDelayMs { get; set; } = 500;

    /// <summary>
    /// Caps exchanges on a single session so local testing doesn't run forever while
    /// there's no real bridge/brain to end the conversation. Not a real design
    /// constraint - remove once the real MQTT bridge (Phase 4) is in place.
    /// </summary>
    public int MaxRequestsPerSession { get; set; } = 10;
}
