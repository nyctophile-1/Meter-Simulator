using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;

namespace ManyMeterSimulator.Framing;

/// <summary>
/// Parses/builds the DLMS-over-TCP/IP Wrapper PDU (IEC 62056-47): an 8-byte header
/// (version, source wPort, destination wPort, length - all big-endian uint16) followed
/// by that many bytes of opaque DLMS APDU payload. This layer never interprets the APDU.
/// </summary>
public static class DlmsWpduFramer
{
    public const int HeaderLength = 8;
    public const ushort ExpectedVersion = 1;

    /// <summary>
    /// Reads the next complete frame from the pipe. Returns null on a graceful EOF that
    /// falls exactly between frames. Throws InvalidDataException on a malformed header
    /// or a connection that closes mid-frame.
    /// </summary>
    public static async ValueTask<WpduFrame?> ReadFrameAsync(PipeReader reader, CancellationToken cancellationToken)
    {
        while (true)
        {
            ReadResult result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            ReadOnlySequence<byte> buffer = result.Buffer;

            if (TryReadFrame(ref buffer, out WpduFrame? frame, out SequencePosition consumed))
            {
                reader.AdvanceTo(consumed);
                return frame;
            }

            if (result.IsCompleted)
            {
                if (buffer.Length == 0)
                {
                    return null;
                }

                throw new InvalidDataException("Connection closed mid-frame.");
            }

            reader.AdvanceTo(buffer.Start, buffer.End);
        }
    }

    private static bool TryReadFrame(ref ReadOnlySequence<byte> buffer, out WpduFrame? frame, out SequencePosition consumed)
    {
        frame = null;
        consumed = buffer.Start;

        if (buffer.Length < HeaderLength)
        {
            return false;
        }

        Span<byte> header = stackalloc byte[HeaderLength];
        buffer.Slice(0, HeaderLength).CopyTo(header);

        ushort version = BinaryPrimitives.ReadUInt16BigEndian(header);
        ushort sourceWPort = BinaryPrimitives.ReadUInt16BigEndian(header[2..]);
        ushort destinationWPort = BinaryPrimitives.ReadUInt16BigEndian(header[4..]);
        ushort length = BinaryPrimitives.ReadUInt16BigEndian(header[6..]);

        if (version != ExpectedVersion)
        {
            throw new InvalidDataException($"Unexpected WPDU version {version}, expected {ExpectedVersion}.");
        }

        var headerEnd = buffer.GetPosition(HeaderLength);
        if (buffer.Slice(headerEnd).Length < length)
        {
            return false;
        }

        byte[] payload = buffer.Slice(headerEnd, length).ToArray();
        // The whole frame (header + payload) is handed to the brain, which owns wrapper handling.
        byte[] raw = buffer.Slice(0, HeaderLength + length).ToArray();
        consumed = buffer.GetPosition(length, headerEnd);
        frame = new WpduFrame(version, sourceWPort, destinationWPort, payload) { Raw = raw };
        return true;
    }

    /// <summary>
    /// Builds a WPDU frame's wire bytes. For responses, callers are expected to swap
    /// source/destination wPort relative to the originating request per the standard's
    /// convention (unconfirmed against real HES samples - see implementation.md).
    /// </summary>
    public static byte[] BuildFrame(ushort sourceWPort, ushort destinationWPort, ReadOnlySpan<byte> payload)
    {
        if (payload.Length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(payload), "DLMS WPDU payload exceeds 65535 bytes.");
        }

        var buffer = new byte[HeaderLength + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(buffer, ExpectedVersion);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2), sourceWPort);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), destinationWPort);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(6), (ushort)payload.Length);
        payload.CopyTo(buffer.AsSpan(HeaderLength));
        return buffer;
    }
}
