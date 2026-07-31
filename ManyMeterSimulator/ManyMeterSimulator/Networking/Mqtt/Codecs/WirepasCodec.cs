using System.Buffers.Binary;
using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using ManyMeterSimulator.Networking.Nic;
using ProtoBuf;

namespace ManyMeterSimulator.Networking.Mqtt.Codecs;

/// <summary>
/// RF MQTT Wirepas (virtual_nics.md §14.2). Two things make this the most error-prone variant:
///
/// <para>
/// <b>1. The framing is asymmetric.</b> HES writes its framing fields as a TRAILER at the END of
/// the request, and expects them as a HEADER at the FRONT of the response — the same five fields in
/// reverse order at the opposite end of the packet. Assuming symmetry (as every other variant here
/// is) produces a codec that decodes HES perfectly and is never understood by it.
/// </para>
///
/// <para>
/// <b>2. The request topic carries more than DLMS.</b> <c>gw-request/send_data/#</c> also carries
/// Wirepas OTAP traffic on endpoints 255/240 — confirmed by live capture, several per minute. Only
/// <c>destination_endpoint == 3</c> is a DLMS pull, mirroring the <c>source_endpoint == 3</c> check
/// HES applies to our uplink.
/// </para>
///
/// NIC-level reassembly is deferred: HES chunks requests at 90 bytes, so a payload over that arrives
/// in pieces we currently report as <see cref="NicDecodeStatus.Unsupported"/>. This is the one
/// variant where inbound fragmentation is real.
/// </summary>
public sealed class WirepasCodec : INicCodec
{
    /// <summary>The DLMS endpoint. Anything else on this topic is OTAP or diagnostics, not ours.</summary>
    public const uint DlmsEndpoint = 3;

    /// <summary>Framing bytes, response direction (header). Request direction uses the same five as a trailer.</summary>
    public const int FramingLength = 5;

    public NicType Nic => NicType.MqttWirepas;

    public IReadOnlyList<string> RequestTopicFilters { get; } = new[] { NicTopics.WirepasRequestFilter };

    public bool TryRoute(NicEnvelope envelope, out NicRoute route)
    {
        route = default;

        GenericMessage? message = TryParse(envelope.Payload);
        SendPacketReq? request = message?.wirepas?.send_packet_req;
        if (request is null)
        {
            return false;
        }

        // OTAP and diagnostics ride the same topic; only endpoint 3 is a DLMS pull.
        if (request.destination_endpoint != DlmsEndpoint)
        {
            return false;
        }

        // Broadcast is not a meter — a real node ignores it for pull purposes, and treating
        // 0xFFFFFFFF as a node id would invent a meter that does not exist.
        if (request.destination_address == uint.MaxValue)
        {
            return false;
        }

        // Parsed once here and carried forward, so Decode never re-parses the same bytes.
        route = new NicRoute(request.destination_address.ToString(), request);
        return true;
    }

    public NicDecodeResult Decode(NicEnvelope envelope, NicRoute route)
    {
        SendPacketReq? request = route.Parsed as SendPacketReq ?? TryParse(envelope.Payload)?.wirepas?.send_packet_req;
        if (request?.payload is null)
        {
            return NicDecodeResult.Malformed("no send_packet_req payload");
        }

        ReadOnlySpan<byte> framed = request.payload;
        if (framed.Length < FramingLength)
        {
            return NicDecodeResult.Malformed($"{framed.Length} bytes is shorter than the {FramingLength}-byte trailer");
        }

        // TRAILER, per MQTTSendCommandClient.GetPacketFragments:
        //   [0..1] frameId LE | [2..n] chunk | [n+1] thisFragment | [n+2] totalFragments | [n+3] length
        ushort frameId = BinaryPrimitives.ReadUInt16LittleEndian(framed);
        int thisFragment = framed[^3];
        int totalFragments = framed[^2];

        // HES applies the same swap guard on the way in; mirror it rather than reject a packet it
        // would have accepted.
        if (thisFragment > totalFragments)
        {
            (totalFragments, thisFragment) = (thisFragment, totalFragments);
        }

        if (totalFragments > 1)
        {
            return NicDecodeResult.Unsupported(
                $"fragmented Wirepas request ({thisFragment}/{totalFragments}) — reassembly not implemented", frameId);
        }

        // Between the 2-byte frameId prefix and the 3-byte trailer.
        return NicDecodeResult.Complete(framed[2..^3].ToArray(), frameId);
    }

    public IReadOnlyList<NicPublish> Encode(
        NicEnvelope request, NicRoute route, ushort frameId, ReadOnlyMemory<byte> dlmsResponse)
    {
        if (dlmsResponse.IsEmpty)
        {
            return Array.Empty<NicPublish>();
        }

        var message = new GenericMessage
        {
            wirepas = new WirepasMessage
            {
                packet_received_event = new PacketReceivedEvent
                {
                    header = new EventHeader
                    {
                        gw_id = GatewayIdFrom(request.Topic),
                        sink_id = SinkIdFrom(request.Topic),
                        event_id = (ulong)Random.Shared.NextInt64(),
                    },
                    source_address = long.Parse(route.NodeId),
                    destination_address = 0,
                    // HES drops any uplink whose source_endpoint is not 3 — this is load-bearing.
                    source_endpoint = DlmsEndpoint,
                    destination_endpoint = DlmsEndpoint,
                    travel_time_ms = 0,
                    rx_time_ms_epoch = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    qos = 1,
                    payload = BuildFramedResponse(frameId, dlmsResponse.Span),
                    hop_count = 1,
                },
            },
        };

        message.wirepas.packet_received_event.payload_size =
            (uint)message.wirepas.packet_received_event.payload.Length;

        using var buffer = new MemoryStream();
        Serializer.Serialize(buffer, message);

        string topic = string.Format(
            NicTopics.WirepasResponseFormat,
            message.wirepas.packet_received_event.header.gw_id,
            message.wirepas.packet_received_event.header.sink_id,
            route.NodeId);

        return new[] { new NicPublish(topic, buffer.ToArray()) };
    }

    /// <summary>
    /// The response framing: a HEADER, not the trailer HES sent us. Layout per
    /// <c>DLMSHandlingFunctions.IsCompletePacket</c> with PullHeaderLength = 5:
    /// <c>[0] length | [1] totalFragments | [2] thisFragment | [3..4] frameId LE | [5..] payload</c>.
    /// </summary>
    public static byte[] BuildFramedResponse(ushort frameId, ReadOnlySpan<byte> dlmsFrame)
    {
        var buffer = new byte[FramingLength + dlmsFrame.Length];

        // 1 byte only, so it wraps past 250 — harmless, because HES reads it solely for bookkeeping
        // and never on the single-fragment path.
        buffer[0] = (byte)(dlmsFrame.Length + FramingLength);
        buffer[1] = 1;   // total fragments
        buffer[2] = 1;   // this fragment (1-based)
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(3), frameId);
        dlmsFrame.CopyTo(buffer.AsSpan(FramingLength));

        return buffer;
    }

    /// <summary>gw-request/send_data/{gatewayId}/{sinkId} — echoed back so the reply looks like it came via the same gateway.</summary>
    private static string GatewayIdFrom(string topic)
    {
        string[] parts = topic.Split('/');
        return parts.Length > 2 ? parts[2] : "sim-gw";
    }

    private static string SinkIdFrom(string topic)
    {
        string[] parts = topic.Split('/');
        return parts.Length > 3 ? parts[3] : "sink1";
    }

    private static GenericMessage? TryParse(byte[] payload)
    {
        try
        {
            using var stream = new MemoryStream(payload, writable: false);
            return Serializer.Deserialize<GenericMessage>(stream);
        }
        catch
        {
            // Non-protobuf or a message shape we do not model. Not an error — the topic carries
            // other traffic — so the caller treats it as "not ours".
            return null;
        }
    }
}
