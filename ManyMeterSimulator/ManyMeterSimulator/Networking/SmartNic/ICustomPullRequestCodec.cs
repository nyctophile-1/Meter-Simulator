using ManyMeterSimulator.Networking.Mqtt;

namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>
/// Optional MQTT codec capability for an endpoint that transports smart-NIC custom-pull bytes
/// rather than a transparent DLMS wrapper. Keeping it separate from <see cref="INicCodec"/>
/// prevents a 32-bit custom frame id from being narrowed into the ordinary DLMS codec contract.
/// </summary>
public interface ICustomPullRequestCodec
{
    bool IsCustomPullRoute(NicRoute route);

    bool TryGetCustomPullPayload(NicRoute route, out ReadOnlyMemory<byte> payload, out string error);
}
