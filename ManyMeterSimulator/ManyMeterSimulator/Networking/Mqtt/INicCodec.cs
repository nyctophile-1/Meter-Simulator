using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// The entire variant-specific surface of an MQTT NIC: which topics it owns, and how to get a node
/// id out of a message. Everything else — admission, sessions, the brain funnel, metrics — is
/// shared and knows nothing about topics or framing.
///
/// <para>
/// NIC-level fragmentation is deliberately deferred: HES never fragments its own direct-4G or
/// Kmesh requests, and the simulator has no radio to constrain its replies, so everything is sent
/// as a single message. Wirepas requests DO arrive fragmented (90-byte chunks) and will need
/// reassembly when that variant is built.
/// </para>
/// </summary>
public interface INicCodec
{
    NicType Nic { get; }

    /// <summary>The request topic filters this codec subscribes to.</summary>
    IReadOnlyList<string> RequestTopicFilters { get; }

    /// <summary>
    /// This codec's wiring in words — logged at startup so the listen/publish contract with HES can
    /// be read off the console instead of inferred from silence. See <see cref="NicTopicPlan"/>.
    /// </summary>
    NicTopicPlan TopicPlan { get; }

    /// <summary>
    /// Answers "which node is this message for?" so it can be handed to that node's worker.
    ///
    /// Runs on the MQTT receive callback, so it must be fast and thread-safe — it holds no state.
    /// Returns false to drop the message (not ours, or unparseable). Anything the codec had to
    /// parse to find the node id is carried forward in <see cref="NicRoute.Parsed"/>.
    /// </summary>
    bool TryRoute(NicEnvelope envelope, out NicRoute route);

    /// <summary>
    /// Unwraps a request into the complete DLMS wrapper frame the brain expects.
    ///
    /// Runs on the meter's own serialized worker, so it may hold per-meter state if a variant ever
    /// needs it (Wirepas reassembly).
    /// </summary>
    NicDecodeResult Decode(NicEnvelope envelope, NicRoute route);

    /// <summary>
    /// Wraps the brain's verbatim reply back up and says where to publish it.
    ///
    /// Gets the original request back so a variant can reuse whatever correlation it needs — the
    /// frame id to echo, the gateway id from the request topic, the parsed protobuf envelope.
    /// Returns an empty list when there is nothing to send.
    /// </summary>
    IReadOnlyList<NicPublish> Encode(NicEnvelope request, NicRoute route, ushort frameId, ReadOnlyMemory<byte> dlmsResponse);
}
