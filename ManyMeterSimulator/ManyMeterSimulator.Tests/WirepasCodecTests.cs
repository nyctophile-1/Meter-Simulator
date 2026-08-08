using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Mqtt.Codecs;
using ManyMeterSimulator.Networking.Nic;
using ProtoBuf;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Wirepas is the variant most likely to be got wrong, for two reasons this file pins directly:
/// the exact framing layout, and the fact that the request topic carries non-DLMS traffic that must
/// be ignored rather than decoded.
///
/// <para>
/// The framing is a 5-byte HEADER in both directions. An earlier reading of the HES source had the
/// request as a TRAILER; the live capture in
/// <see cref="Decode_ReadsARealCapturedRequest"/> disproves it, and that test is the anchor — it is
/// bytes off the wire rather than bytes derived from our own reading of anything.
/// </para>
/// </summary>
public class WirepasCodecTests
{
    private static readonly WirepasCodec Codec = new();

    private const string RequestTopic = "gw-request/send_data/DEMO100175/sink2";

    /// <summary>Builds a downlink exactly as HES does: protobuf envelope wrapping a HEADER-framed payload.</summary>
    private static NicEnvelope HesRequest(uint nodeId, byte[] dlms, ushort frameId, uint destinationEndpoint = 3)
    {
        byte[] framed = HesHeaderFrame(dlms, frameId);

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
    /// The framing HES actually puts on a request, as observed on the wire: a 5-byte HEADER, the
    /// same layout it expects back on the uplink.
    /// </summary>
    private static byte[] HesHeaderFrame(byte[] payload, ushort frameId)
    {
        var buffer = new byte[5 + payload.Length];
        buffer[0] = (byte)(payload.Length + 5);           // length, including the header
        buffer[1] = 1;                                    // totalFragments
        buffer[2] = 1;                                    // thisFragment
        BitConverter.GetBytes(frameId).CopyTo(buffer, 3); // frameId LE
        payload.CopyTo(buffer, 5);
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

    // ── The framing ───────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// THE anchor test: a real <c>send_packet_req</c> captured from the live broker on 2026-08-08,
    /// addressed to simulated node 507 on endpoint 3. These are bytes off the wire, so they outrank
    /// any reading of the HES source — and they are what disproved the "request is a trailer"
    /// conclusion in virtual_nics.md §14.2.
    ///
    /// <para>
    /// The inner payload is <c>2C 01 01 AD 01</c> then the DLMS wrapper. Read as a header every
    /// field agrees with the packet: length 0x2C = 44 = the real payload length, fragment 1 of 1,
    /// frameId 429. Read as a trailer the same bytes claim 255 fragments, which is how a perfectly
    /// good request came to be discarded as "unsupported fragmentation" and answered with silence.
    /// </para>
    /// </summary>
    [Fact]
    public void Decode_ReadsARealCapturedRequest()
    {
        const string capturedHex =
            "0A4932470A0E0802120A6469726563745F74637010FB03180320032801322C2C0101AD01" +
            "000100100001001F601DA109060760857405080101BE10040E01000000065F1F0400621E5DFFFF";

        var envelope = new NicEnvelope(RequestTopic, Convert.FromHexString(capturedHex), DateTimeOffset.UtcNow);

        Assert.True(Codec.TryRoute(envelope, out NicRoute route));
        Assert.Equal("507", route.NodeId);

        NicDecodeResult result = Codec.Decode(envelope, route);

        Assert.True(result.IsComplete);
        Assert.Equal(429, result.FrameId);

        // Exactly the DLMS wrapper frame the brain expects: 8-byte WPDU header declaring 31 bytes,
        // then a 31-byte AARQ. Nothing of the NIC framing may survive into it.
        Assert.Equal(
            Convert.FromHexString("000100100001001F601DA109060760857405080101BE10040E01000000065F1F0400621E5DFFFF"),
            result.DlmsFrame);
    }

    [Fact]
    public void Decode_ReadsHesHeaderFraming()
    {
        byte[] dlms = [0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB];

        Codec.TryRoute(HesRequest(506, dlms, 0x1234), out NicRoute route);
        NicDecodeResult result = Codec.Decode(HesRequest(506, dlms, 0x1234), route);

        Assert.True(result.IsComplete);
        Assert.Equal(dlms, result.DlmsFrame);
        Assert.Equal(0x1234, result.FrameId);
    }

    [Fact]
    public void Encode_WritesHeaderFraming()
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
    }

    /// <summary>
    /// A real meter's uplink, quoted from the HES log: <c>5F 01 09 AC 49</c> — 95 bytes, and the
    /// swap quirk in action (1/9 written as totalFragments = 1, thisFragment = 9). Pins that our
    /// reader agrees with actual hardware, not just with our own writer.
    /// </summary>
    [Fact]
    public void HesParse_AgreesWithARealMetersUplinkHeader()
    {
        byte[] realUplinkHeader = [0x5F, 0x01, 0x09, 0xAC, 0x49];

        int totalFragments = realUplinkHeader[1];
        int thisFragment = realUplinkHeader[2];
        if (thisFragment > totalFragments)
        {
            (totalFragments, thisFragment) = (thisFragment, totalFragments);
        }

        Assert.Equal(95, realUplinkHeader[0]);
        Assert.Equal(9, totalFragments);
        Assert.Equal(1, thisFragment);
        Assert.Equal(0x49AC, BitConverter.ToUInt16(realUplinkHeader, 3));
    }

    /// <summary>
    /// Round-trips one direction into the other. Both use the same layout now, so this is a
    /// consistency check rather than the asymmetry guard it used to be — the layout itself is
    /// pinned by <see cref="Decode_ReadsARealCapturedRequest"/> against real bytes.
    /// </summary>
    [Fact]
    public void RequestAndResponseFraming_RoundTrip()
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

    /// <summary>
    /// A first fragment is buffered, not refused. This used to report <c>Unsupported</c> while
    /// inbound reassembly was deferred, which silently dropped HES's ciphered HLS association —
    /// the only request it ever fragments. See <see cref="WirepasFragmentReassemblyTests"/> for the
    /// full round trip on real captured fragments.
    /// </summary>
    [Fact]
    public void Decode_BuffersAFragmentedRequestInsteadOfRefusingIt()
    {
        byte[] framed = HesHeaderFrame([1, 2, 3], 9);
        framed[1] = 4;   // totalFragments

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

        // Nothing to answer yet — the reply is produced when the last fragment arrives.
        Assert.Equal(NicDecodeStatus.Incomplete, result.Status);
        Assert.Null(result.DlmsFrame);
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
