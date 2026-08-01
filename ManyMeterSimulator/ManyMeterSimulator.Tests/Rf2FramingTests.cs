using ManyMeterSimulator.Networking.Mqtt.Codecs;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// RF2 custom framing (endpoint 13). Vectors are built by porting HES's own writer
/// (<c>CustomPullCommandPayload.ClassToArray</c>) and its header/CRC readers, since no RF2 packet
/// has been captured yet.
///
/// The template-driven widths are the sharp edge here: frame id is 2 or 4 bytes and node ids are
/// 3 or 4, chosen by the meter template rather than signalled in the packet. Guess wrong and every
/// field after the header silently shifts.
/// </summary>
public class Rf2FramingTests
{
    /// <summary>Literal port of HES's ClassToArray over CustomPullCommandPayload: Pack=1, little-endian.</summary>
    private static byte[] HesBuildRequest(
        uint frameId, uint fromNode, uint toNode, byte commandType, byte selector,
        uint valueFrom, uint valueTo, int frameIdBytes, int nodeIdBytes)
    {
        var bytes = new List<byte>();
        int total = 3 + frameIdBytes + (2 * nodeIdBytes) + 3 + 8;

        bytes.Add((byte)total);   // PacketLength
        bytes.Add(1);             // TotalFragments
        bytes.Add(1);             // FragmentId
        bytes.AddRange(BitConverter.GetBytes(frameId).Take(frameIdBytes));
        bytes.AddRange(BitConverter.GetBytes(fromNode).Take(nodeIdBytes));
        bytes.AddRange(BitConverter.GetBytes(toNode).Take(nodeIdBytes));
        bytes.Add(commandType);
        bytes.Add(selector);
        bytes.Add(8);             // DataLength
        bytes.AddRange(BitConverter.GetBytes(valueFrom));
        bytes.AddRange(BitConverter.GetBytes(valueTo));

        return bytes.ToArray();
    }

    [Theory]
    [InlineData(2, 3)]   // legacy template
    [InlineData(4, 4)]   // NewHeader / FG23 family
    [InlineData(2, 4)]
    public void ParsesARequestAtEitherTemplateWidth(int frameIdBytes, int nodeIdBytes)
    {
        const uint frameId = 4299;
        const uint fromNode = 1;
        const uint toNode = 112233;

        byte[] wire = HesBuildRequest(
            frameId, fromNode, toNode, commandType: 12, selector: 1,
            valueFrom: 1_700_000_000, valueTo: 1_700_003_600, frameIdBytes, nodeIdBytes);

        Assert.True(Rf2Framing.TryParseRequest(wire, frameIdBytes, nodeIdBytes, out Rf2Framing.CustomRequest request));

        Assert.Equal(frameId, request.FrameId);
        Assert.Equal(fromNode, request.FromNodeId);
        Assert.Equal(toNode, request.ToNodeId);
        Assert.Equal(12, request.CommandType);
        Assert.Equal(1, request.DataSelector);
        Assert.Equal(1_700_000_000u, request.ValueFrom);
        Assert.Equal(1_700_003_600u, request.ValueTo);
    }

    /// <summary>
    /// The widths are not self-describing, so reading a 4-byte-node packet as 3-byte must not
    /// silently succeed with shifted values -- it should produce visibly wrong output, which this
    /// pins so the failure mode is understood rather than discovered in the field.
    /// </summary>
    [Fact]
    public void ReadingAtTheWrongWidth_ShiftsEveryFieldAfterIt()
    {
        byte[] wire = HesBuildRequest(4299, 1, 112233, 12, 1, 1_700_000_000, 1_700_003_600, 4, 4);

        Assert.True(Rf2Framing.TryParseRequest(wire, frameIdBytes: 2, nodeIdBytes: 3, out Rf2Framing.CustomRequest wrong));
        Assert.NotEqual(112233u, wrong.ToNodeId);
    }

    [Fact]
    public void RejectsAPayloadTooShortToHoldTheFixedFields()
    {
        Assert.False(Rf2Framing.TryParseRequest(new byte[6], 2, 3, out _));
    }

    [Fact]
    public void NewHeaderResponse_MatchesTheDocumentedLayout()
    {
        byte[] body = [0xAA, 0xBB, 0xCC];

        byte[] framed = Rf2Framing.BuildNewHeaderResponse(magicNumber: 0x12345678, frameId: 0x0000A1B2, body);

        Assert.Equal(
        [
            0x78, 0x56, 0x34, 0x12,   // MagicNumber LE  (template-id mapping key)
            0x0F, 0x00,               // PacketLength = 3 + 12
            0x01,                     // TotalFrags
            0x01,                     // ThisFrag
            0xB2, 0xA1, 0x00, 0x00,   // FrameID LE
            0xAA, 0xBB, 0xCC,
        ], framed);
    }

    [Fact]
    public void LegacyHeaderResponse_MatchesRf1sLayout()
    {
        byte[] framed = Rf2Framing.BuildLegacyHeaderResponse(0x1234, [0xAA, 0xBB, 0xCC]);

        Assert.Equal([0x08, 0x01, 0x01, 0x34, 0x12, 0xAA, 0xBB, 0xCC], framed);
    }

    /// <summary>
    /// CRC-CCITT/FALSE (poly 0x1021, init 0xFFFF), checked against the standard "123456789" vector
    /// which gives 0x29B1.
    ///
    /// HES computes it, takes little-endian bytes, then swaps them — so the net effect of the
    /// "swap" is simply that the CRC goes on the wire BIG-endian, unlike every other multi-byte
    /// field in these protocols. Worth stating plainly, because reading the swap as an oddity
    /// rather than as an endianness choice is how it gets dropped.
    /// </summary>
    [Fact]
    public void Crc_IsCcittFalse_AndGoesOnTheWireBigEndian()
    {
        byte[] crc = Rf2Framing.Crc("123456789"u8);

        Assert.Equal([0x29, 0xB1], crc);
    }

    [Fact]
    public void Crc_IsDeterministic_AndChangesWithTheData()
    {
        byte[] a = Rf2Framing.Crc([1, 2, 3, 4]);
        byte[] b = Rf2Framing.Crc([1, 2, 3, 5]);

        Assert.Equal(a, Rf2Framing.Crc([1, 2, 3, 4]));
        Assert.NotEqual(a, b);
    }
}
