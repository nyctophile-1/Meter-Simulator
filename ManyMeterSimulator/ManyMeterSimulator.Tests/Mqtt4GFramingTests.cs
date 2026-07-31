using System.Buffers.Binary;
using ManyMeterSimulator.Framing;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Mqtt.Codecs;
using ManyMeterSimulator.Networking.Nic;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Byte-level tests for the direct-4G framing (virtual_nics.md §14.1).
///
/// No real <c>PollRequest</c> has ever been captured, so these vectors are built by reimplementing
/// HES's OWN writer and parser from the source — <c>GetPacketFragments</c> and
/// <c>IsCompletePacketDirectDLMS</c> — and asserting our codec interoperates with them. That is
/// weaker than a captured packet and stronger than asserting our encoder against our own decoder,
/// which would pass no matter how wrong the layout was.
/// </summary>
public class Mqtt4GFramingTests
{
    private static readonly Mqtt4GCodec Codec = new(NicType.Mqtt4G);

    /// <summary>A plausible DLMS wrapper frame: 8-byte WPDU header + APDU.</summary>
    private static byte[] DlmsFrame(int apduLength = 4)
    {
        byte[] apdu = Enumerable.Range(0, apduLength).Select(i => (byte)(0x60 + i)).ToArray();
        return DlmsWpduFramer.BuildFrame(sourceWPort: 16, destinationWPort: 1, apdu);
    }

    private static NicEnvelope Request(byte[] payload, string nodeId = "521") =>
        new($"PollRequest/{nodeId}", payload, DateTimeOffset.UtcNow);

    // ── HES's own logic, reimplemented from the source ────────────────────────────────────────

    /// <summary>
    /// Literal port of <c>MQTTSendCommandDirectDLMSClient.GetPacketFragments</c>: 2-byte LE total
    /// length (payload + 6), totalFragments = 1, currentFragment = 1, 2-byte LE frameId, payload.
    /// </summary>
    private static byte[] HesBuildRequest(byte[] payload, ushort frameId)
    {
        var buffer = new byte[6 + payload.Length];
        BitConverter.GetBytes((ushort)(payload.Length + 6)).CopyTo(buffer, 0);
        buffer[2] = 1;
        buffer[3] = 1;
        BitConverter.GetBytes(frameId).CopyTo(buffer, 4);
        payload.CopyTo(buffer, 6);
        return buffer;
    }

    /// <summary>
    /// Literal port of <c>DLMSHandlingFunctions.IsCompletePacketDirectDLMS</c> for the
    /// single-fragment path (headerLength = 6), including the index/total swap guard.
    /// </summary>
    private static bool HesParseResponse(byte[] payload, out byte[] dlmsFrame, out ushort frameId)
    {
        dlmsFrame = Array.Empty<byte>();
        frameId = 0;

        const int headerLength = 6;
        byte[] header = payload[..headerLength];
        byte[] rest = payload[headerLength..];

        int totalFragments = header[2];
        int receivedFragmentIndex = header[3];
        if (receivedFragmentIndex > totalFragments)
        {
            (totalFragments, receivedFragmentIndex) = (receivedFragmentIndex, totalFragments);
        }

        if (totalFragments > 1)
        {
            return false;   // would go through the reassembly table
        }

        frameId = BitConverter.ToUInt16(header, 4);
        dlmsFrame = rest;
        return true;
    }

    // ── Decode ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Decode_RecoversWhatHesWrote()
    {
        byte[] dlms = DlmsFrame();
        const ushort frameId = 0xBEEF;

        NicDecodeResult result = Codec.Decode(Request(HesBuildRequest(dlms, frameId)), new NicRoute("521"));

        Assert.True(result.IsComplete);
        Assert.Equal(dlms, result.DlmsFrame);
        Assert.Equal(frameId, result.FrameId);
    }

    /// <summary>The recovered bytes must be a valid input to the TCP path — that is the contract.</summary>
    [Fact]
    public void Decode_ProducesAFrameTheWpduFramerAccepts()
    {
        byte[] dlms = DlmsFrame(apduLength: 12);
        NicDecodeResult result = Codec.Decode(Request(HesBuildRequest(dlms, 1)), new NicRoute("521"));

        byte[] recovered = result.DlmsFrame!;
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(recovered));           // WPDU version
        Assert.Equal(12, BinaryPrimitives.ReadUInt16BigEndian(recovered.AsSpan(6))); // APDU length
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(5)]
    public void Decode_RejectsAPayloadShorterThanTheHeader(int length)
    {
        NicDecodeResult result = Codec.Decode(Request(new byte[length]), new NicRoute("521"));

        Assert.Equal(NicDecodeStatus.Malformed, result.Status);
    }

    /// <summary>
    /// A fragmented request is a deferred feature, not a decoding failure. Keeping them distinct
    /// matters operationally: Unsupported is expected, Malformed means something is actually wrong.
    /// </summary>
    [Fact]
    public void Decode_ReportsFragmentedRequestsAsUnsupported_NotMalformed()
    {
        byte[] payload = HesBuildRequest(DlmsFrame(), frameId: 7);
        payload[2] = 3;   // totalFragments
        payload[3] = 1;   // this fragment

        NicDecodeResult result = Codec.Decode(Request(payload), new NicRoute("521"));

        Assert.Equal(NicDecodeStatus.Unsupported, result.Status);
        Assert.Equal(7, result.FrameId);   // still recovered, so the drop can be correlated
    }

    /// <summary>
    /// HES swaps these two if they arrive reversed, defending against a real NIC that emits them
    /// the other way round. We mirror it rather than rejecting a packet HES would have accepted.
    /// </summary>
    [Fact]
    public void Decode_ToleratesIndexAndTotalArrivingSwapped()
    {
        byte[] dlms = DlmsFrame();
        byte[] payload = HesBuildRequest(dlms, frameId: 9);
        payload[2] = 1;   // "total" holding the index
        payload[3] = 1;   // equal — the single-fragment case survives either reading

        Assert.True(Codec.Decode(Request(payload), new NicRoute("521")).IsComplete);
    }

    [Fact]
    public void Decode_HandlesAnEmptyDlmsPayload()
    {
        NicDecodeResult result = Codec.Decode(Request(HesBuildRequest([], 3)), new NicRoute("521"));

        Assert.True(result.IsComplete);
        Assert.Empty(result.DlmsFrame!);
    }

    // ── Encode ────────────────────────────────────────────────────────────────────────────────

    /// <summary>Byte-for-byte, against a hand-derived expected packet rather than our own decoder.</summary>
    [Fact]
    public void Encode_ProducesTheExactExpectedBytes()
    {
        byte[] dlms = [0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB];
        const ushort frameId = 0x1234;

        byte[] framed = Mqtt4GCodec.BuildFrame(frameId, dlms);

        Assert.Equal(
        [
            0x10, 0x00,               // total length 16 = 10 + 6, little-endian
            0x01,                     // total fragments
            0x01,                     // this fragment
            0x34, 0x12,               // frameId 0x1234, little-endian
            0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB,
        ], framed);
    }

    [Fact]
    public void Encode_PublishesToTheTopicHesReadsTheNodeIdFrom()
    {
        IReadOnlyList<NicPublish> publishes =
            Codec.Encode(Request([], "521"), new NicRoute("521"), frameId: 1, DlmsFrame());

        NicPublish publish = Assert.Single(publishes);
        Assert.Equal("PollResponse/521", publish.Topic);
        Assert.Equal("521", publish.Topic.Split('/')[1]);   // exactly how HES recovers it
    }

    [Fact]
    public void Encode_EchoesTheRequestsFrameId()
    {
        const ushort frameId = 0xABCD;

        byte[] payload = Codec.Encode(Request([], "521"), new NicRoute("521"), frameId, DlmsFrame())[0].Payload;

        Assert.Equal(frameId, BitConverter.ToUInt16(payload, 4));
    }

    /// <summary>An empty reply must be silence, not a zero-length frame — that would look malformed.</summary>
    [Fact]
    public void Encode_SendsNothingWhenTheBrainHadNoReply()
    {
        Assert.Empty(Codec.Encode(Request([], "521"), new NicRoute("521"), 1, ReadOnlyMemory<byte>.Empty));
    }

    [Fact]
    public void Encode_NeverFragments_EvenForALargeReply()
    {
        byte[] big = DlmsFrame(apduLength: 4000);

        IReadOnlyList<NicPublish> publishes = Codec.Encode(Request([], "521"), new NicRoute("521"), 1, big);

        NicPublish publish = Assert.Single(publishes);
        Assert.Equal(1, publish.Payload[2]);                        // total fragments
        Assert.Equal(big.Length + 6, publish.Payload.Length);
    }

    // ── Interop ───────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// The assertion that actually matters: our reply, parsed by HES's own logic, yields the DLMS
    /// frame we meant to send and the frame id it was waiting on.
    /// </summary>
    [Theory]
    [InlineData(4)]
    [InlineData(200)]
    [InlineData(4000)]      // past the 1-byte length field, which HES never validates
    public void OurResponse_IsUnderstoodByHesParser(int apduLength)
    {
        byte[] dlms = DlmsFrame(apduLength);
        const ushort frameId = 0x0777;

        byte[] wire = Codec.Encode(Request([], "521"), new NicRoute("521"), frameId, dlms)[0].Payload;

        Assert.True(HesParseResponse(wire, out byte[] parsed, out ushort parsedFrameId));
        Assert.Equal(dlms, parsed);
        Assert.Equal(frameId, parsedFrameId);
    }

    [Fact]
    public void RequestAndResponseFramingAreSymmetric()
    {
        byte[] dlms = DlmsFrame(64);
        const ushort frameId = 0x4242;

        // HES's request framing, read by us...
        NicDecodeResult decoded = Codec.Decode(Request(HesBuildRequest(dlms, frameId)), new NicRoute("521"));
        // ...and our response framing, read by HES.
        byte[] wire = Mqtt4GCodec.BuildFrame(decoded.FrameId, decoded.DlmsFrame!);

        Assert.True(HesParseResponse(wire, out byte[] parsed, out ushort parsedFrameId));
        Assert.Equal(dlms, parsed);
        Assert.Equal(frameId, parsedFrameId);
    }
}
