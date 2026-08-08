using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Mqtt.Codecs;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Xunit;
using Xunit.Abstractions;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Wirepas is the only direction where HES fragments, and it only ever does so for one message: the
/// ciphered HLS association it opens at Step 4. Everything before that — the public AARQ, the
/// invocation-counter read, the release — fits inside one 90-byte chunk.
///
/// <para>
/// So while multi-fragment requests were reported as <c>Unsupported</c>, a pull ran perfectly
/// through Steps 1-3 and then went silent, with no error logged by the simulator and none by HES.
/// These are the two real fragments captured off the live broker on 2026-08-08 for simulated node
/// 507, frame id 475.
/// </para>
/// </summary>
public class WirepasFragmentReassemblyTests
{
    private readonly ITestOutputHelper _output;

    public WirepasFragmentReassemblyTests(ITestOutputHelper output) => _output = output;

    private const string RequestTopic = "gw-request/send_data/gw_w1/sink1";

    /// <summary>Fragment 1 of 2 — payload framing <c>5F 02 01 DB 01</c>, then 90 bytes.</summary>
    private const string Fragment1Hex =
        "0A7C327A0A0E0815120A6469726563745F74637010FB03180320032801325F5F0201DB01" +
        "000100300001005F605DA109060760857405080103A60A040841424344454647488A0207" +
        "808B0760857405080202AC1280100F02515B5E690D7117034951744C3736BE230421211F" +
        "3000003C5908834DB01AF352565BFD274C96";

    /// <summary>Fragment 2 of 2 — framing <c>12 02 02 DB 01</c>, then the remaining 13 bytes.</summary>
    private const string Fragment2Hex =
        "0A2F322D0A0E0816120A6469726563745F74637010FB031803200328013212120202DB01" +
        "B32E854F130188D2F311923D39";

    private static NicEnvelope Envelope(string hex) =>
        new(RequestTopic, Convert.FromHexString(hex), DateTimeOffset.UtcNow);

    private static NicDecodeResult Feed(WirepasCodec codec, string hex)
    {
        var envelope = Envelope(hex);
        Assert.True(codec.TryRoute(envelope, out NicRoute route));
        return codec.Decode(envelope, route);
    }

    [Fact]
    public void TwoRealFragments_ReassembleIntoOneCompleteFrame()
    {
        var codec = new WirepasCodec();

        NicDecodeResult first = Feed(codec, Fragment1Hex);
        Assert.Equal(NicDecodeStatus.Incomplete, first.Status);

        NicDecodeResult second = Feed(codec, Fragment2Hex);
        Assert.True(second.IsComplete);
        Assert.Equal(475, second.FrameId);

        byte[] frame = second.DlmsFrame!;
        _output.WriteLine($"reassembled ({frame.Length} bytes): {Convert.ToHexString(frame)}");

        // The wrapper's own length field is the independent check: 8-byte header + 95 = 103.
        Assert.Equal(103, frame.Length);
        Assert.Equal(95, (frame[6] << 8) | frame[7]);
        Assert.Equal(0x30, frame[3]);   // client 0x30 — the secure association
        Assert.Equal(0x60, frame[8]);   // AARQ
    }

    /// <summary>Order is not guaranteed on RF, so the tail may arrive first.</summary>
    [Fact]
    public void FragmentsArrivingOutOfOrder_StillReassemble()
    {
        var codec = new WirepasCodec();

        Assert.Equal(NicDecodeStatus.Incomplete, Feed(codec, Fragment2Hex).Status);

        NicDecodeResult result = Feed(codec, Fragment1Hex);

        Assert.True(result.IsComplete);
        Assert.Equal(103, result.DlmsFrame!.Length);
    }

    /// <summary>A repeated fragment is discarded, not concatenated twice — HES's own rule.</summary>
    [Fact]
    public void DuplicateFragments_AreDropped()
    {
        var codec = new WirepasCodec();

        Feed(codec, Fragment1Hex);
        Feed(codec, Fragment1Hex);

        NicDecodeResult result = Feed(codec, Fragment2Hex);

        Assert.True(result.IsComplete);
        Assert.Equal(103, result.DlmsFrame!.Length);
    }

    /// <summary>
    /// The whole point: the reassembled frame is a real ciphered HLS AARQ, and the brain must answer
    /// it with an AARE addressed back to client 0x30. This is the exchange HES's Step 4 waits for.
    /// </summary>
    [Fact]
    public void TheReassembledSecureAarq_IsAnsweredByTheBrain()
    {
        var codec = new WirepasCodec();
        Feed(codec, Fragment1Hex);
        NicDecodeResult decoded = Feed(codec, Fragment2Hex);
        Assert.True(decoded.IsComplete);

        var meter = new DLMSMeter(507, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        var session = new DLMSServerSession(
            meter, Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        session.Initialize(true);

        byte[] reply = session.HandleRequest(decoded.DlmsFrame!) ?? Array.Empty<byte>();

        _output.WriteLine($"reply ({reply.Length} bytes): {Convert.ToHexString(reply)}");

        Assert.NotEmpty(reply);
        Assert.Equal(0x30, reply[5]);   // addressed back to the secure client
        Assert.Equal(0x61, reply[8]);   // AARE
    }
}
