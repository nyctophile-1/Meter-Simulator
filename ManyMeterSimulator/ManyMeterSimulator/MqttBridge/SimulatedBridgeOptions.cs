namespace ManyMeterSimulator.MqttBridge;

public class SimulatedBridgeOptions
{
    public const string SectionName = "SimulatedBridge";

    public int RoundTripDelayMs { get; set; } = 500;
}
