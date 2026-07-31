using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Xunit;
using Xunit.Abstractions;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Replays the EXACT public-association AARQ captured from the live HES on 2026-07-30 against a
/// real brain session, so the reply can be inspected offline instead of guessed at from a broker.
///
/// Captured from <c>PollRequest/526</c>:
/// <code>
///   2D 00 01 01 CB 10                    ← 4G header: len 45, frag 1/1, frameId 4299
///   00 01 00 10 00 01 00 1F              ← DLMS wrapper: v1, client 16, server 1, 31 bytes
///   60 1D A1 09 06 07 60 85 74 05 08 01 01 ...  ← AARQ, context 2.16.756.5.8.1.1 (LN, no ciphering)
/// </code>
/// </summary>
public class HesAarqReplayTests
{
    private readonly ITestOutputHelper _output;

    public HesAarqReplayTests(ITestOutputHelper output) => _output = output;

    /// <summary>The DLMS wrapper frame exactly as it arrived, with the 6-byte NIC header stripped.</summary>
    private static byte[] CapturedAarqFrame() => Convert.FromHexString(
        "00010010000100" + "1F" +
        "601DA109060760857405080101BE10040E01000000065F1F0400621E5DFFFF");

    private static DLMSServerSession BuildSession(string template = "SA1231166HP_values.xml")
    {
        var meter = new DLMSMeter(526, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        var session = new DLMSServerSession(meter, Path.Combine(AppContext.BaseDirectory, "Templates", template));
        session.Initialize(true);
        return session;
    }

    [Fact]
    public void TheRealHesAarq_ProducesAnAcceptingAare()
    {
        DLMSServerSession session = BuildSession();

        byte[] reply = session.HandleRequest(CapturedAarqFrame()) ?? Array.Empty<byte>();

        _output.WriteLine($"reply ({reply.Length} bytes): {Convert.ToHexString(reply)}");
        Assert.NotEmpty(reply);

        // Strip the 8-byte wrapper to reach the APDU.
        byte[] apdu = reply[8..];
        _output.WriteLine($"apdu  ({apdu.Length} bytes): {Convert.ToHexString(apdu)}");
        Assert.Equal(0x61, apdu[0]);   // AARE tag

        // association-result is an INTEGER inside [APPLICATION 1]: A2 03 02 01 <result>.
        // 0 = accepted, 1 = rejected-permanent, 2 = rejected-transient. Anything but 0 means the
        // HES client would give up right after the association, which is exactly what we observed.
        int resultIndex = IndexOf(apdu, [0xA2, 0x03, 0x02, 0x01]);
        Assert.True(resultIndex >= 0, $"no association-result found in AARE: {Convert.ToHexString(apdu)}");

        byte result = apdu[resultIndex + 4];
        _output.WriteLine($"association-result = {result} (0 = accepted)");

        // result-source-diagnostic follows: A3 05 A1 03 02 01 <diagnostic>
        int diagIndex = IndexOf(apdu, [0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01]);
        if (diagIndex >= 0)
        {
            _output.WriteLine($"acse-service-user diagnostic = {apdu[diagIndex + 6]}");
        }

        Assert.Equal(0, result);
    }

    /// <summary>
    /// A connectionless NIC has no close event, so the same brain session sees a second AARQ with
    /// no release in between — exactly what happens when HES polls a meter again after the virtual
    /// session was idle-reaped. If the second association is not accepted, every poll after the
    /// first one dies immediately after the handshake.
    /// </summary>
    [Fact]
    public void ASecondAarq_OnTheSameSession_IsAlsoAccepted()
    {
        DLMSServerSession session = BuildSession();

        byte[] first = session.HandleRequest(CapturedAarqFrame()) ?? Array.Empty<byte>();
        byte[] second = session.HandleRequest(CapturedAarqFrame()) ?? Array.Empty<byte>();

        _output.WriteLine($"1st AARE ({first.Length}): {Convert.ToHexString(first)}");
        _output.WriteLine($"2nd AARE ({second.Length}): {Convert.ToHexString(second)}");

        Assert.NotEmpty(second);

        byte[] apdu = second[8..];
        int resultIndex = IndexOf(apdu, [0xA2, 0x03, 0x02, 0x01]);
        Assert.True(resultIndex >= 0, $"no association-result in the 2nd AARE: {Convert.ToHexString(apdu)}");

        byte result = apdu[resultIndex + 4];
        int diagIndex = IndexOf(apdu, [0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01]);
        _output.WriteLine($"2nd association-result = {result}, diagnostic = {(diagIndex >= 0 ? apdu[diagIndex + 6] : -1)}");

        Assert.Equal(0, result);
    }

    /// <summary>
    /// End-to-end on the REAL captured request: NIC unwrap → brain → NIC wrap, showing the exact
    /// bytes that go back on the wire.
    ///
    /// The frame id is the correlation token — HES resolves the meter from the node id in the topic
    /// and the command from (meterNo, frameId) in the packet — so it has to survive the round trip
    /// unchanged, and in the same little-endian order HES wrote it.
    /// </summary>
    [Fact]
    public void FullRoundTrip_OnTheCapturedRequest_EchoesTheFrameId()
    {
        // Exactly as captured from PollRequest/526, including the 6-byte NIC header.
        byte[] onTheWireIn = Convert.FromHexString(
            "2D000101CB10" + "00010010000100" + "1F" +
            "601DA109060760857405080101BE10040E01000000065F1F0400621E5DFFFF");

        var codec = new ManyMeterSimulator.Networking.Mqtt.Codecs.Mqtt4GCodec(
            ManyMeterSimulator.Networking.Nic.NicType.Mqtt4G);
        var route = new ManyMeterSimulator.Networking.Mqtt.NicRoute("526");
        var envelope = new ManyMeterSimulator.Networking.Mqtt.NicEnvelope(
            "PollRequest/526", onTheWireIn, DateTimeOffset.UtcNow);

        ManyMeterSimulator.Networking.Mqtt.NicDecodeResult decoded = codec.Decode(envelope, route);
        Assert.True(decoded.IsComplete);

        byte[] reply = BuildSession().HandleRequest(decoded.DlmsFrame!)!;

        ManyMeterSimulator.Networking.Mqtt.NicPublish publish =
            codec.Encode(envelope, route, decoded.FrameId, reply)[0];

        _output.WriteLine($"IN   topic : PollRequest/526");
        _output.WriteLine($"IN   bytes : {Convert.ToHexString(onTheWireIn)}");
        _output.WriteLine($"     header: {Convert.ToHexString(onTheWireIn[..6])}  frameId={decoded.FrameId}");
        _output.WriteLine("");
        _output.WriteLine($"OUT  topic : {publish.Topic}");
        _output.WriteLine($"OUT  bytes : {Convert.ToHexString(publish.Payload)}");
        _output.WriteLine($"     header: {Convert.ToHexString(publish.Payload[..6])}  frameId={BitConverter.ToUInt16(publish.Payload, 4)}");

        // The frame id HES sent must come back byte-identical, in the same two positions.
        Assert.Equal(4299, decoded.FrameId);
        Assert.Equal(4299, BitConverter.ToUInt16(publish.Payload, 4));
        Assert.Equal(onTheWireIn[4], publish.Payload[4]);
        Assert.Equal(onTheWireIn[5], publish.Payload[5]);
        Assert.Equal("PollResponse/526", publish.Topic);
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return i;
            }
        }

        return -1;
    }
}
