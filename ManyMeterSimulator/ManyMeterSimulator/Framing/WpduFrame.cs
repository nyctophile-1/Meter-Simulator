namespace ManyMeterSimulator.Framing;

public sealed record WpduFrame(ushort Version, ushort SourceWPort, ushort DestinationWPort, byte[] Payload);
