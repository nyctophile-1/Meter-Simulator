using System.Buffers.Binary;
using ManyMeterSimulator.Networking.Mqtt.Codecs;

namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>
/// The template-selected physical layout of an endpoint-13 request. The layout is not
/// self-describing: HES chooses its frame/node widths from the meter template before serializing.
/// </summary>
public readonly record struct CustomPullWireProfile(
    int FrameIdBytes,
    int NodeIdBytes,
    bool RequiresRequestCrc)
{
    public static readonly CustomPullWireProfile Legacy = new(2, 3, false);
    public static readonly CustomPullWireProfile LegacyFg23 = new(2, 4, false);
    public static readonly CustomPullWireProfile NewHeader = new(4, 4, true);

    public int FixedPayloadLength => 3 + FrameIdBytes + (2 * NodeIdBytes) + 3 + 8;

    public int PacketLength => FixedPayloadLength + (RequiresRequestCrc ? 2 : 0);

    public bool IsValid => FrameIdBytes is 2 or 4 && NodeIdBytes is 3 or 4;
}

/// <summary>
/// A lossless endpoint-13 request after its physical framing has been checked. Command values stay
/// as raw 32-bit words because HES uses the same fields for epochs, entry ranges, float bit
/// patterns, and gap bitmaps. Command interpretation belongs to the command catalogue.
/// </summary>
public readonly record struct CustomPullRequest(
    byte TotalFragments,
    byte FragmentId,
    uint FrameId,
    uint FromNodeId,
    uint ToNodeId,
    byte RawCommandType,
    CustomPullWireSelector Selector,
    byte DataLength,
    uint ValueFromBits,
    uint ValueToBits)
{
    public int ValueFromSigned => unchecked((int)ValueFromBits);

    public int ValueToSigned => unchecked((int)ValueToBits);
}

/// <summary>Exact HES <c>CustomCommandDataSelector</c> wire values.</summary>
public enum CustomPullWireSelector : byte
{
    GetWithoutData = 1,
    SetWithData = 2,
    SetWithDate = 3,
    GetWithEntryRange = 4,
    GetWithDateRange = 5,
    GetLatestEntriesRange = 6,
}

/// <summary>
/// Strict decoder for the custom request body produced by HES's
/// <c>CustomPullCommandPayload.ClassToArray</c>. It intentionally does not decide whether a
/// command is implemented; a syntactically valid unknown command must reach the capability
/// catalogue so it can be reported as unsupported rather than malformed.
/// </summary>
public static class CustomPullRequestParser
{
    public static bool TryParse(
        ReadOnlySpan<byte> payload,
        CustomPullWireProfile profile,
        out CustomPullRequest request,
        out string? error)
    {
        request = default;
        error = null;

        if (!profile.IsValid)
        {
            error = $"invalid custom wire profile F={profile.FrameIdBytes}, N={profile.NodeIdBytes}";
            return false;
        }

        if (payload.Length != profile.PacketLength)
        {
            error = $"payload length {payload.Length} does not equal template-required {profile.PacketLength}";
            return false;
        }

        int packetLength = payload[0];
        if (packetLength != payload.Length)
        {
            error = $"packet length {packetLength} does not equal received length {payload.Length}";
            return false;
        }

        if (profile.RequiresRequestCrc)
        {
            ReadOnlySpan<byte> expected = Rf2Framing.Crc(payload[..^2]);
            if (!payload[^2..].SequenceEqual(expected))
            {
                error = "custom request CRC is invalid";
                return false;
            }
        }

        int at = 1;
        byte totalFragments = payload[at++];
        byte fragmentId = payload[at++];
        if (totalFragments != 1 || fragmentId != 1)
        {
            error = $"custom request fragmentation {fragmentId}/{totalFragments} is not supported";
            return false;
        }

        uint frameId = ReadUnsignedLittleEndian(payload.Slice(at, profile.FrameIdBytes));
        at += profile.FrameIdBytes;
        uint fromNodeId = ReadUnsignedLittleEndian(payload.Slice(at, profile.NodeIdBytes));
        at += profile.NodeIdBytes;
        uint toNodeId = ReadUnsignedLittleEndian(payload.Slice(at, profile.NodeIdBytes));
        at += profile.NodeIdBytes;

        byte commandType = payload[at++];
        byte selectorValue = payload[at++];
        if (!Enum.IsDefined((CustomPullWireSelector)selectorValue))
        {
            error = $"unknown custom selector {selectorValue}";
            return false;
        }

        var selector = (CustomPullWireSelector)selectorValue;
        byte dataLength = payload[at++];
        byte expectedDataLength = ExpectedDataLength(selector);
        if (dataLength != expectedDataLength)
        {
            error = $"selector {selector} requires DataLength {expectedDataLength}, not {dataLength}";
            return false;
        }

        uint valueFrom = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(at, 4));
        at += 4;
        uint valueTo = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(at, 4));

        request = new CustomPullRequest(
            totalFragments,
            fragmentId,
            frameId,
            fromNodeId,
            toNodeId,
            commandType,
            selector,
            dataLength,
            valueFrom,
            valueTo);
        return true;
    }

    private static byte ExpectedDataLength(CustomPullWireSelector selector) => selector switch
    {
        CustomPullWireSelector.GetWithoutData => 0,
        CustomPullWireSelector.SetWithData or CustomPullWireSelector.SetWithDate => 4,
        CustomPullWireSelector.GetWithEntryRange
            or CustomPullWireSelector.GetWithDateRange
            or CustomPullWireSelector.GetLatestEntriesRange => 8,
        _ => throw new ArgumentOutOfRangeException(nameof(selector)),
    };

    private static uint ReadUnsignedLittleEndian(ReadOnlySpan<byte> bytes) => bytes.Length switch
    {
        2 => BinaryPrimitives.ReadUInt16LittleEndian(bytes),
        3 => (uint)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16)),
        4 => BinaryPrimitives.ReadUInt32LittleEndian(bytes),
        _ => throw new ArgumentOutOfRangeException(nameof(bytes)),
    };
}
