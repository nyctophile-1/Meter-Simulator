using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Mqtt.Codecs;
using ManyMeterSimulator.Networking.Nic;
using ProtoBuf;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Wirepas is the variant most likely to be got wrong, for two reasons this file pins directly:
/// the framing is asymmetric (trailer in, header out), and the request topic carries non-DLMS
/// traffic that must be ignored rather than decoded.
/// </summary>
public class WirepasCodecTests
{
    private static readonly WirepasCodec Codec = new();

    private const string RequestTopic = "gw-request/send_data/DEMO100175/sink2";

    /// <summary>Builds a downlink exactly as HES does: protobuf envelope wrapping a TRAILER-framed payload.</summary>
    private static NicEnvelope HesRequest(uint nodeId, byte[] dlms, ushort frameId, uint destinationEndpoint = 3)
    {
        byte[] framed = HesTrailerFrame(dlms, frameId);

        var message = new GenericMessage
        {
            wirepas = new WirepasMessage
            {
                send_packet_req = new SendPacketReq
                {
                    header = new RequestHeader { req_id = 1, sink_id = "sink2" },
                    destination_address = nodeId,
                    source_endpoint = 3,
                    destination_endpoint = destinationEndpoint,
                    qos = 1,
                    payload = framed,
                },
            },
        };

        using var buffer = new MemoryStream();
        Serializer.Serialize(buffer, message);
        return new NicEnvelope(RequestTopic, buffer.ToArray(), DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Literal port of <c>MQTTSendCommandClient.GetPacketFragments</c> for a single chunk:
    /// frameId LE, payload, fragmentId, totalFragments, length — a TRAILER.
    /// </summary>
    private static byte[] HesTrailerFrame(byte[] payload, ushort frameId)
    {
        var buffer = new byte[2 + payload.Length + 3];
        BitConverter.GetBytes(frameId).CopyTo(buffer, 0);
        payload.CopyTo(buffer, 2);
        buffer[^3] = 1;                                   // fragmentId
        buffer[^2] = 1;                                   // totalFragments
        buffer[^1] = (byte)(payload.Length + 5);          // payloadLength
        return buffer;
    }

    /// <summary>
    /// Literal port of <c>DLMSHandlingFunctions.IsCompletePacket</c> (PullHeaderLength = 5) — how
    /// HES reads our uplink. A HEADER, not a trailer.
    /// </summary>
    private static bool HesParseResponse(byte[] framed, out byte[] dlms, out ushort frameId)
    {
        dlms = Array.Empty<byte>();
        frameId = 0;

        byte[] header = framed[..5];
        int totalFragments = header[1];
        int thisFragment = header[2];
        if (thisFragment > totalFragments)
        {
            (totalFragments, thisFragment) = (thisFragment, totalFragments);
        }

        if (totalFragments > 1)
        {
            return false;
        }

        frameId = BitConverter.ToUInt16(header, 3);
        dlms = framed[5..];
        return true;
    }

    // ── Routing: the OTAP filter ──────────────────────────────────────────────────────────────

    [Fact]
    public void Routes_ADlmsRequestOnEndpoint3()
    {
        Assert.True(Codec.TryRoute(HesRequest(112233, [1, 2, 3], 7), out NicRoute route));
        Assert.Equal("112233", route.NodeId);
        Assert.NotNull(route.Parsed);   // parsed once, carried forward
    }

    /// <summary>
    /// The live capture showed several OTAP messages per minute on this topic, all on endpoints
    /// 255/240. Decoding those as DLMS would produce a steady stream of phantom errors.
    /// </summary>
    [Theory]
    [InlineData(240u)]   // OTAP
    [InlineData(255u)]
    [InlineData(1u)]
    public void Ignores_NonDlmsEndpoints(uint destinationEndpoint)
    {
        Assert.False(Codec.TryRoute(HesRequest(112233, [1, 2, 3], 7, destinationEndpoint), out _));
    }

    /// <summary>Broadcast is not a meter; treating 0xFFFFFFFF as a node id would invent one.</summary>
    [Fact]
    public void Ignores_TheBroadcastAddress()
    {
        Assert.False(Codec.TryRoute(HesRequest(uint.MaxValue, [1, 2, 3], 7), out _));
    }

    [Fact]
    public void Ignores_NonProtobufPayloads()
    {
        var junk = new NicEnvelope(RequestTopic, [0xFF, 0xFE, 0xFD, 0xFC], DateTimeOffset.UtcNow);
        Assert.False(Codec.TryRoute(junk, out _));
    }

    /// <summary>
    /// The real OTAP packets captured from the live broker on 2026-07-30. These must all be
    /// ignored — this is the regression test for the filter that stops phantom errors.
    /// </summary>
    [Theory]
    [InlineData("0A2832260A120894D4A5B0B5D4CE9EF601120573696E6B3210FFFFFFFF0F18FF0120F001280132021900")]
    [InlineData("0A2632240A1208B89CF7C080D6F4ADEF01120573696E6B3210E9EC0618FF0120F001280132021900")]
    [InlineData("0A2632240A1108C8F5E7B3868CD1DF1F120573696E6B33108A9AEF3A18FF0120F001280132021900")]
    public void Ignores_RealCapturedOtapTraffic(string payloadHex)
    {
        var envelope = new NicEnvelope(RequestTopic, Convert.FromHexString(payloadHex), DateTimeOffset.UtcNow);

        Assert.False(Codec.TryRoute(envelope, out _));
    }

    // ── The asymmetry ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Decode_ReadsHesTrailerFraming()
    {
        byte[] dlms = [0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB];

        Codec.TryRoute(HesRequest(506, dlms, 0x1234), out NicRoute route);
        NicDecodeResult result = Codec.Decode(HesRequest(506, dlms, 0x1234), route);

        Assert.True(result.IsComplete);
        Assert.Equal(dlms, result.DlmsFrame);
        Assert.Equal(0x1234, result.FrameId);
    }

    [Fact]
    public void Encode_WritesHeaderFraming_NotATrailer()
    {
        byte[] dlms = [0xAA, 0xBB, 0xCC];

        byte[] framed = WirepasCodec.BuildFramedResponse(0x1234, dlms);

        Assert.Equal(
        [
            0x08,         // length = 3 + 5
            0x01,         // total fragments
            0x01,         // this fragment
            0x34, 0x12,   // frameId LE
            0xAA, 0xBB, 0xCC,
        ], framed);

        // And explicitly NOT the trailer layout — the framing fields are at the FRONT.
        Assert.NotEqual(0x34, framed[^3]);
    }

    /// <summary>
    /// The test that stops someone "simplifying" the two directions into one shared layout: the
    /// request trailer and the response header are read by different HES code and must stay
    /// independently correct.
    /// </summary>
    [Fact]
    public void RequestTrailerAndResponseHeader_AreIndependentlyCorrect()
    {
        byte[] dlms = [0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x02, 0x61, 0x29];
        const ushort frameId = 0x0777;

        Codec.TryRoute(HesRequest(506, dlms, frameId), out NicRoute route);
        NicDecodeResult decoded = Codec.Decode(HesRequest(506, dlms, frameId), route);
        Assert.True(decoded.IsComplete);

        byte[] uplink = WirepasCodec.BuildFramedResponse(decoded.FrameId, decoded.DlmsFrame!);

        Assert.True(HesParseResponse(uplink, out byte[] parsed, out ushort parsedFrameId));
        Assert.Equal(dlms, parsed);
        Assert.Equal(frameId, parsedFrameId);
    }

    [Fact]
    public void Decode_ReportsFragmentedRequestsAsUnsupported()
    {
        byte[] framed = HesTrailerFrame([1, 2, 3], 9);
        framed[^2] = 4;   // totalFragments

        var message = new GenericMessage
        {
            wirepas = new WirepasMessage
            {
                send_packet_req = new SendPacketReq
                {
                    header = new RequestHeader { req_id = 1, sink_id = "sink2" },
                    destination_address = 506,
                    source_endpoint = 3,
                    destination_endpoint = 3,
                    qos = 1,
                    payload = framed,
                },
            },
        };
        using var buffer = new MemoryStream();
        Serializer.Serialize(buffer, message);
        var envelope = new NicEnvelope(RequestTopic, buffer.ToArray(), DateTimeOffset.UtcNow);

        Codec.TryRoute(envelope, out NicRoute route);
        NicDecodeResult result = Codec.Decode(envelope, route);

        Assert.Equal(NicDecodeStatus.Unsupported, result.Status);
        Assert.Equal(9, result.FrameId);
    }

    // ── The uplink envelope ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// HES drops any uplink whose source_endpoint is not 3, and reads the node id from
    /// source_address. Both are load-bearing.
    /// </summary>
    [Fact]
    public void Encode_ProducesAnUplinkHesWouldAccept()
    {
        byte[] dlms = [0x61, 0x29, 0xA1, 0x09];

        Codec.TryRoute(HesRequest(506, [1], 5), out NicRoute route);
        NicPublish publish = Codec.Encode(HesRequest(506, [1], 5), route, 5, dlms)[0];

        using var stream = new MemoryStream(publish.Payload);
        GenericMessage message = Serializer.Deserialize<GenericMessage>(stream);
        PacketReceivedEvent uplink = message.wirepas.packet_received_event;

        Assert.Equal(3u, uplink.source_endpoint);       // HES filters on exactly this
        Assert.Equal(506, uplink.source_address);
        Assert.Equal((uint)uplink.payload.Length, uplink.payload_size);

        Assert.True(HesParseResponse(uplink.payload, out byte[] parsed, out ushort frameId));
        Assert.Equal(dlms, parsed);
        Assert.Equal(5, frameId);
    }

    /// <summary>The reply goes back via the gateway and sink the request came through.</summary>
    [Fact]
    public void Encode_EchoesTheGatewayAndSinkFromTheRequestTopic()
    {
        Codec.TryRoute(HesRequest(506, [1], 5), out NicRoute route);

        NicPublish publish = Codec.Encode(HesRequest(506, [1], 5), route, 5, new byte[] { 1, 2 })[0];

        Assert.StartsWith("gw-event/received_data/DEMO100175/sink2/", publish.Topic);
        Assert.EndsWith("/3/3", publish.Topic);   // the endpoint pair HES subscribes on
    }

    [Fact]
    public void Encode_SendsNothingWhenTheBrainHadNoReply()
    {
        Codec.TryRoute(HesRequest(506, [1], 5), out NicRoute route);

        Assert.Empty(Codec.Encode(HesRequest(506, [1], 5), route, 5, ReadOnlyMemory<byte>.Empty));
    }
}
