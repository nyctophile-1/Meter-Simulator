using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using ManyMeterSimulator.Networking.Mqtt;
using ProtoBuf;

namespace ManyMeterSimulator.Networking.CustomPush;

/// <summary>Only the Wirepas transport envelope for a custom scheduled push.</summary>
public static class WirepasCustomPushEnvelope
{
    public static NicPublish Create(
        string gatewayId, string sinkId, string nodeId, uint endpoint, ReadOnlySpan<byte> framedPayload)
    {
        if (string.IsNullOrWhiteSpace(gatewayId)) throw new ArgumentException("Gateway is required.", nameof(gatewayId));
        if (string.IsNullOrWhiteSpace(sinkId)) throw new ArgumentException("Sink is required.", nameof(sinkId));
        if (!uint.TryParse(nodeId, out uint node)) throw new ArgumentException("Wirepas node id must be an unsigned integer.", nameof(nodeId));

        var message = new GenericMessage
        {
            wirepas = new WirepasMessage
            {
                packet_received_event = new PacketReceivedEvent
                {
                    header = new EventHeader { gw_id = gatewayId, sink_id = sinkId, event_id = (ulong)Random.Shared.NextInt64() },
                    source_address = node,
                    destination_address = 0,
                    source_endpoint = endpoint,
                    destination_endpoint = endpoint,
                    qos = 1,
                    travel_time_ms = 0,
                    hop_count = 1,
                    rx_time_ms_epoch = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    payload = framedPayload.ToArray(),
                    payload_size = (uint)framedPayload.Length,
                },
            },
        };

        using var stream = new MemoryStream();
        Serializer.Serialize(stream, message);
        return new NicPublish($"gw-event/received_data/{gatewayId}/{sinkId}/{nodeId}/{endpoint}/{endpoint}", stream.ToArray());
    }
}
