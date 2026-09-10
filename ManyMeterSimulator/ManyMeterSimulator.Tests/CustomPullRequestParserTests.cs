using System.Buffers.Binary;
using ManyMeterSimulator.Networking.Mqtt.Codecs;
using ManyMeterSimulator.Networking.SmartNic;

namespace ManyMeterSimulator.Tests;

public class CustomPullRequestParserTests
{
    [Theory]
    [MemberData(nameof(Profiles))]
    public void ParsesTheExactTemplateSelectedWireLayout(CustomPullWireProfile profile)
    {
        byte[] wire = Build(
            profile,
            frameId: 0xA1B2C3D4,
            fromNode: 0x01020304,
            toNode: 0x00112233,
            commandType: 4,
            selector: CustomPullWireSelector.GetWithDateRange,
            valueFrom: 1_700_000_000,
            valueTo: 1_700_003_600);

        Assert.True(CustomPullRequestParser.TryParse(wire, profile, out CustomPullRequest request, out string? error), error);
        Assert.Equal(1, request.TotalFragments);
        Assert.Equal(1, request.FragmentId);
        Assert.Equal(Truncate(0xA1B2C3D4, profile.FrameIdBytes), request.FrameId);
        Assert.Equal(Truncate(0x01020304, profile.NodeIdBytes), request.FromNodeId);
        Assert.Equal(Truncate(0x00112233, profile.NodeIdBytes), request.ToNodeId);
        Assert.Equal(4, request.RawCommandType);
        Assert.Equal(CustomPullWireSelector.GetWithDateRange, request.Selector);
        Assert.Equal(8, request.DataLength);
        Assert.Equal(1_700_000_000u, request.ValueFromBits);
        Assert.Equal(1_700_003_600u, request.ValueToBits);
    }

    [Fact]
    public void NewHeaderRequest_RequiresTheHesCcittFalseTrailer()
    {
        byte[] wire = Build(
            CustomPullWireProfile.NewHeader,
            frameId: 5,
            fromNode: 42,
            toNode: 42,
            commandType: 4,
            selector: CustomPullWireSelector.GetWithoutData,
            valueFrom: 0,
            valueTo: 0);

        wire[^1] ^= 0x01;

        Assert.False(CustomPullRequestParser.TryParse(
            wire,
            CustomPullWireProfile.NewHeader,
            out _,
            out string? error));
        Assert.Equal("custom request CRC is invalid", error);
    }

    [Fact]
    public void LegacyRequest_DoesNotInventARequestCrc()
    {
        byte[] wire = Build(
            CustomPullWireProfile.Legacy,
            frameId: 5,
            fromNode: 42,
            toNode: 42,
            commandType: 4,
            selector: CustomPullWireSelector.GetWithoutData,
            valueFrom: 0,
            valueTo: 0);

        Assert.True(CustomPullRequestParser.TryParse(
            wire,
            CustomPullWireProfile.Legacy,
            out _,
            out string? error), error);
    }

    [Theory]
    [InlineData(CustomPullWireSelector.GetWithoutData, 8)]
    [InlineData(CustomPullWireSelector.SetWithData, 0)]
    [InlineData(CustomPullWireSelector.SetWithDate, 8)]
    [InlineData(CustomPullWireSelector.GetWithEntryRange, 4)]
    [InlineData(CustomPullWireSelector.GetWithDateRange, 4)]
    [InlineData(CustomPullWireSelector.GetLatestEntriesRange, 0)]
    public void RejectsASelectorWhoseDeclaredLengthDoesNotMatchHesContract(
        CustomPullWireSelector selector,
        byte declaredLength)
    {
        byte[] wire = Build(
            CustomPullWireProfile.Legacy,
            frameId: 5,
            fromNode: 42,
            toNode: 42,
            commandType: 4,
            selector,
            valueFrom: 0,
            valueTo: 0);

        int dataLengthOffset = 3 + CustomPullWireProfile.Legacy.FrameIdBytes +
            (2 * CustomPullWireProfile.Legacy.NodeIdBytes) + 2;
        wire[dataLengthOffset] = declaredLength;

        Assert.False(CustomPullRequestParser.TryParse(
            wire,
            CustomPullWireProfile.Legacy,
            out _,
            out string? error));
        Assert.Contains("requires DataLength", error);
    }

    [Fact]
    public void RejectsPacketLengthAndFragmentationThatTheSmartNicCannotSafelyExecute()
    {
        byte[] wire = Build(
            CustomPullWireProfile.Legacy,
            frameId: 5,
            fromNode: 42,
            toNode: 42,
            commandType: 4,
            selector: CustomPullWireSelector.GetWithEntryRange,
            valueFrom: 1,
            valueTo: 3);

        wire[0]--;
        Assert.False(CustomPullRequestParser.TryParse(wire, CustomPullWireProfile.Legacy, out _, out string? lengthError));
        Assert.Contains("packet length", lengthError);

        wire = Build(
            CustomPullWireProfile.Legacy,
            frameId: 5,
            fromNode: 42,
            toNode: 42,
            commandType: 4,
            selector: CustomPullWireSelector.GetWithEntryRange,
            valueFrom: 1,
            valueTo: 3);
        wire[1] = 2;
        Assert.False(CustomPullRequestParser.TryParse(wire, CustomPullWireProfile.Legacy, out _, out string? fragmentError));
        Assert.Contains("fragmentation", fragmentError);
    }

    public static IEnumerable<object[]> Profiles()
    {
        yield return [CustomPullWireProfile.Legacy];
        yield return [CustomPullWireProfile.LegacyFg23];
        yield return [CustomPullWireProfile.NewHeader];
    }

    private static byte[] Build(
        CustomPullWireProfile profile,
        uint frameId,
        uint fromNode,
        uint toNode,
        byte commandType,
        CustomPullWireSelector selector,
        uint valueFrom,
        uint valueTo)
    {
        var wire = new byte[profile.PacketLength];
        wire[0] = checked((byte)wire.Length);
        wire[1] = 1;
        wire[2] = 1;

        int at = 3;
        WriteUnsignedLittleEndian(wire.AsSpan(at, profile.FrameIdBytes), frameId);
        at += profile.FrameIdBytes;
        WriteUnsignedLittleEndian(wire.AsSpan(at, profile.NodeIdBytes), fromNode);
        at += profile.NodeIdBytes;
        WriteUnsignedLittleEndian(wire.AsSpan(at, profile.NodeIdBytes), toNode);
        at += profile.NodeIdBytes;
        wire[at++] = commandType;
        wire[at++] = (byte)selector;
        wire[at++] = selector switch
        {
            CustomPullWireSelector.GetWithoutData => 0,
            CustomPullWireSelector.SetWithData or CustomPullWireSelector.SetWithDate => 4,
            _ => 8,
        };
        BinaryPrimitives.WriteUInt32LittleEndian(wire.AsSpan(at, 4), valueFrom);
        at += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(wire.AsSpan(at, 4), valueTo);

        if (profile.RequiresRequestCrc)
        {
            Rf2Framing.Crc(wire[..^2]).CopyTo(wire, wire.Length - 2);
        }

        return wire;
    }

    private static void WriteUnsignedLittleEndian(Span<byte> destination, uint value)
    {
        for (int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)(value >> (i * 8));
        }
    }

    private static uint Truncate(uint value, int bytes) => bytes == 4 ? value : value & ((1u << (bytes * 8)) - 1);
}
