namespace ManyMeterSimulator.Framing;

public sealed record WpduFrame(ushort Version, ushort SourceWPort, ushort DestinationWPort, byte[] Payload)
{
    /// <summary>
    /// The complete on-wire frame bytes (8-byte WPDU header + payload) exactly as read from
    /// the stream. The brain (Gurux WRAPPER server) owns wrapper parse/build, so it needs the
    /// whole frame — the header carries the DLMS addresses it acts on — not just the payload.
    /// </summary>
    public byte[] Raw { get; init; } = System.Array.Empty<byte>();
}
