using System.Buffers.Binary;

namespace ManyMeterSimulator.Networking.CustomPush;

/// <summary>
/// Frames a flat custom scheduled-push body exactly as HES's
/// <c>DLMSHandlingFunctions.IsCompletePacket*</c> removes it.  It intentionally knows nothing
/// about the vendor body: field packing belongs to the custom-template packer.
/// </summary>
public static class CustomPushFramer
{
    public static byte[] Frame(
        ReadOnlySpan<byte> body,
        CustomPushHeaderKind headerKind,
        uint frameId,
        uint? magicNumber = null)
    {
        return headerKind switch
        {
            CustomPushHeaderKind.Old => FrameOld(body, checked((ushort)frameId)),
            CustomPushHeaderKind.New => magicNumber is uint magic
                ? FrameNew(body, frameId, magic)
                : throw new ArgumentException("New custom push framing requires the HES template magic number.", nameof(magicNumber)),
            _ => throw new ArgumentOutOfRangeException(nameof(headerKind)),
        };
    }

    /// <summary>
    /// HES strips ten bytes for legacy custom templates.  Its reassembler reads only bytes 0..4;
    /// the opaque tail is emitted as zeroes, never guessed as protocol data.
    /// </summary>
    public static byte[] FrameOld(ReadOnlySpan<byte> body, ushort frameId)
    {
        var packet = new byte[10 + body.Length];
        packet[0] = unchecked((byte)packet.Length);
        packet[1] = 1;
        packet[2] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(3), frameId);
        body.CopyTo(packet.AsSpan(10));
        return packet;
    }

    /// <summary>12-byte custom header: magic, total packet length, fragment count/index and frame id.</summary>
    public static byte[] FrameNew(ReadOnlySpan<byte> body, uint frameId, uint magicNumber)
    {
        var packet = new byte[12 + body.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(packet, magicNumber);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(4), checked((ushort)packet.Length));
        packet[6] = 1;
        packet[7] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(8), frameId);
        body.CopyTo(packet.AsSpan(12));
        return packet;
    }
}
