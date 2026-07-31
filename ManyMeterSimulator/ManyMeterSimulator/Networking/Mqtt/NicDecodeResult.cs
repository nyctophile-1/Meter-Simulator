namespace ManyMeterSimulator.Networking.Mqtt;

public enum NicDecodeStatus
{
    /// <summary>A complete DLMS wrapper frame was recovered.</summary>
    Complete,

    /// <summary>
    /// Part of a multi-fragment message. Reassembly is deliberately not implemented yet — see
    /// <see cref="Unsupported"/>.
    /// </summary>
    Incomplete,

    /// <summary>
    /// Well-formed, but uses a feature this codec does not implement yet (today: NIC-level
    /// fragmentation). Distinct from <see cref="Malformed"/> so a deferred feature never gets
    /// mistaken for a decoding bug in the logs.
    /// </summary>
    Unsupported,

    /// <summary>Not a packet this codec understands. On a healthy system this should stay at zero.</summary>
    Malformed,
}

/// <summary>
/// The outcome of unwrapping one inbound message.
///
/// <see cref="DlmsFrame"/> is the COMPLETE wrapper frame (8-byte WPDU header + APDU) — byte for
/// byte what the TCP listener reads off a socket. If it would be a valid input to the TCP path,
/// the codec is correct.
/// </summary>
public readonly record struct NicDecodeResult(NicDecodeStatus Status, byte[]? DlmsFrame, ushort FrameId, string? Detail = null)
{
    public bool IsComplete => Status == NicDecodeStatus.Complete && DlmsFrame is not null;

    public static NicDecodeResult Complete(byte[] dlmsFrame, ushort frameId) =>
        new(NicDecodeStatus.Complete, dlmsFrame, frameId);

    public static NicDecodeResult Unsupported(string detail, ushort frameId = 0) =>
        new(NicDecodeStatus.Unsupported, null, frameId, detail);

    public static NicDecodeResult Malformed(string detail) =>
        new(NicDecodeStatus.Malformed, null, 0, detail);
}

/// <summary>One outbound broker message.</summary>
public sealed record NicPublish(string Topic, byte[] Payload);
