using System.Buffers.Binary;
using System.Collections.Concurrent;
using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using ManyMeterSimulator.Networking.Nic;
using ProtoBuf;

namespace ManyMeterSimulator.Networking.Mqtt.Codecs;

/// <summary>
/// RF MQTT Wirepas (virtual_nics.md §14.2). Two things make this the most error-prone variant:
///
/// <para>
/// <b>1. The framing is a 5-byte HEADER in BOTH directions</b> —
/// <c>[0] length | [1] totalFragments | [2] thisFragment | [3..4] frameId LE | [5..] payload</c>.
/// </para>
///
/// <para>
/// This corrects virtual_nics.md §14.2, which read <c>MQTTSendCommandClient.GetPacketFragments</c>
/// as writing a TRAILER on the request and concluded the two directions were asymmetric. A live
/// capture (2026-08-08) says otherwise. A real request for node 507 carried:
/// <code>
///   2C 01 01 AD 01 | 00 01 00 10 00 01 00 1F | 60 1D ... FF FF
///   ^len=44 ^1of1  ^frameId=429   ^DLMS wrapper (8-byte WPDU header + 31-byte AARQ)
/// </code>
/// Read as a header every field is self-consistent — the length byte equals the real payload length
/// and the fragment counts are 1/1. Read as a trailer the same bytes give totalFragments = 255, so
/// the packet was being discarded as an unsupported fragmented request. Since that path logs at
/// Debug and records no metric, the symptom was a Wirepas NIC that silently answered nothing.
/// </para>
///
/// <para>
/// Real meter uplinks in the HES log use this same header (<c>5F 01 09 AC 49</c> = 95 bytes,
/// fragment 1 of 9, frameId 0x49AC), which is also exactly what
/// <see cref="BuildFramedResponse"/> writes — so the response direction was already right, and the
/// two directions simply match.
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

    /// <summary>Framing bytes — a 5-byte header, the same layout in both directions.</summary>
    public const int FramingLength = 5;

    /// <summary>
    /// Partial fragment sets are abandoned after this long. Wirepas is the only inbound direction
    /// that fragments, and a set that never completes would otherwise pin memory per node.
    /// </summary>
    private readonly FragmentReassembler _fragments = new(TimeSpan.FromSeconds(30));

    public NicType Nic => NicType.MqttWirepas;

    public IReadOnlyList<string> RequestTopicFilters { get; } = new[] { NicTopics.WirepasRequestFilter };

    public NicTopicPlan TopicPlan { get; } = new(
        Subscribe: NicTopics.WirepasRequestFilter,
        NodeIdSource: "protobuf send_packet_req.destination_address (requires destination_endpoint == 3; OTAP 255/240 is ignored)",
        Publish: "gw-event/received_data/{gwId}/{sinkId}/{nodeId}/3/3, gateway and sink echoed from the request",
        HesExpects: "gw-event/received_data/+/+/+/3/3, and drops anything whose source_endpoint != 3",
        Framing: "5-byte HEADER both directions (len | totalFrag | thisFrag | frameId2) — verified against a live capture");

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
            return NicDecodeResult.Malformed($"{framed.Length} bytes is shorter than the {FramingLength}-byte header");
        }

        // HEADER — the same layout we write on the way out. See the class remarks for why this is
        // NOT the trailer the HES source appeared to describe.
        //   [0] length | [1] totalFragments | [2] thisFragment | [3..4] frameId LE | [5..] payload
        int totalFragments = framed[1];
        int thisFragment = framed[2];
        ushort frameId = BinaryPrimitives.ReadUInt16LittleEndian(framed[3..5]);

        // HES applies the same swap guard on the way in; mirror it rather than reject a packet it
        // would have accepted. Real meter uplinks genuinely arrive as e.g. 01/09 meaning 1-of-9.
        if (thisFragment > totalFragments)
        {
            (totalFragments, thisFragment) = (thisFragment, totalFragments);
        }

        ReadOnlySpan<byte> chunk = framed[FramingLength..];

        // Single fragment short-circuits with no state at all, exactly as HES's own reassembler
        // does. This is the overwhelmingly common case — only the ciphered HLS association is big
        // enough to be split.
        if (totalFragments <= 1)
        {
            return NicDecodeResult.Complete(chunk.ToArray(), frameId);
        }

        return _fragments.Add(route.NodeId, frameId, thisFragment, totalFragments, chunk);
    }

    /// <summary>
    /// Inbound reassembly for the one direction where fragmentation is real.
    ///
    /// <para>
    /// HES chunks Wirepas requests at 90 bytes, and Wirepas is the only variant where it fragments
    /// at all. A public-client AARQ (44 bytes) fits in one message, so the whole pull works until
    /// HES opens the ciphered HLS association — 103 bytes — which arrives as 2 fragments. While
    /// those were reported as <c>Unsupported</c> the meter went silent at exactly that point, with
    /// no error on either side.
    /// </para>
    ///
    /// <para>
    /// Semantics follow HES's own reassembler (virtual_nics.md §14.4): keyed by node and frame id,
    /// completion is count-based rather than length-based, fragments are concatenated in ascending
    /// index order, and a repeated index is discarded rather than overwriting.
    /// </para>
    /// </summary>
    private sealed class FragmentReassembler
    {
        private readonly TimeSpan _timeout;
        private readonly ConcurrentDictionary<(string NodeId, ushort FrameId), PendingSet> _pending = new();

        public FragmentReassembler(TimeSpan timeout) => _timeout = timeout;

        public NicDecodeResult Add(
            string nodeId, ushort frameId, int index, int total, ReadOnlySpan<byte> chunk)
        {
            if (index < 1 || index > total)
            {
                return NicDecodeResult.Malformed($"fragment index {index} outside 1..{total}");
            }

            (string, ushort) key = (nodeId, frameId);
            byte[]? assembled;

            while (true)
            {
                PendingSet set = _pending.GetOrAdd(key, _ => new PendingSet(total));

                lock (set)
                {
                    // A restarted set for the same (node, frame): HES gave up and began again, or
                    // the previous attempt aged out. Holding the stale halves would splice two
                    // different messages into one plausible-looking frame, so drop and retry with a
                    // fresh set rather than reusing this one.
                    if (set.Total == total && DateTimeOffset.UtcNow - set.StartedUtc <= _timeout)
                    {
                        assembled = set.Put(index, chunk);
                        break;
                    }
                }

                _pending.TryRemove(new KeyValuePair<(string, ushort), PendingSet>(key, set));
            }

            if (assembled is null)
            {
                return NicDecodeResult.Incomplete();
            }

            _pending.TryRemove(key, out _);
            return NicDecodeResult.Complete(assembled, frameId);
        }

        private sealed class PendingSet
        {
            private readonly byte[]?[] _chunks;

            public PendingSet(int total)
            {
                Total = total;
                _chunks = new byte[]?[total];
                StartedUtc = DateTimeOffset.UtcNow;
            }

            public int Total { get; }

            public DateTimeOffset StartedUtc { get; }

            /// <summary>Stores one fragment; returns the whole frame once every index has arrived.</summary>
            public byte[]? Put(int index, ReadOnlySpan<byte> chunk)
            {
                // Duplicates are dropped, not overwritten — the same rule HES applies.
                _chunks[index - 1] ??= chunk.ToArray();

                var size = 0;
                foreach (byte[]? part in _chunks)
                {
                    if (part is null)
                    {
                        return null;
                    }

                    size += part.Length;
                }

                var frame = new byte[size];
                var offset = 0;
                foreach (byte[]? part in _chunks)
                {
                    part!.CopyTo(frame, offset);
                    offset += part.Length;
                }

                return frame;
            }
        }
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
