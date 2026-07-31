namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>One inbound broker message, before any variant-specific interpretation.</summary>
public sealed record NicEnvelope(string Topic, byte[] Payload, DateTimeOffset ReceivedAtUtc);

/// <summary>
/// The outcome of <see cref="INicCodec.TryRoute"/>: which node a message is for, plus whatever the
/// codec had to parse to find that out.
///
/// <see cref="Parsed"/> exists so the protobuf variants (Wirepas, Kmesh) parse once rather than
/// twice — their node id is inside the payload, so routing already costs a full decode, and
/// throwing that away would double the work on the receive path. Null for the 4G variants, whose
/// node id is in the topic.
/// </summary>
public readonly record struct NicRoute(string NodeId, object? Parsed = null);
