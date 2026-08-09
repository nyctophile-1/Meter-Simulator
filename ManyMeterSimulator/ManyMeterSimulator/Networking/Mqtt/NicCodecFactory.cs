using ManyMeterSimulator.Networking.Mqtt.Codecs;
using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// Builds a codec instance for a transport.
///
/// <para>
/// Codecs used to be DI singletons shared by every consumer. They cannot be, once several brokers
/// serve one transport: <see cref="WirepasCodec"/> reassembles inbound fragments in a dictionary
/// keyed by (node id, frame id), and a single shared instance would interleave fragments arriving
/// from two different brokers into one buffer. The resulting corrupted APDU would look exactly like
/// a codec bug (network_registry.md §5.4).
/// </para>
///
/// <para>
/// Giving each binding its OWN codec fixes that without threading a binding key through
/// <see cref="INicCodec.Decode"/> and every implementation of it. Codecs are cheap — the only state
/// any of them holds is that reassembly table — so per-binding instances cost nothing.
/// </para>
/// </summary>
public sealed class NicCodecFactory
{
    /// <summary>
    /// A codec for this transport, or null if it has none. Always a FRESH instance: two callers
    /// sharing one would reintroduce the cross-broker reassembly problem this type exists to solve.
    /// </summary>
    public INicCodec? Create(NicType transport) => NicTypes.TransportFor(transport) switch
    {
        NicType.Mqtt4G => new Mqtt4GCodec(NicType.Mqtt4G),
        NicType.MqttWirepas => new WirepasCodec(),
        NicType.MqttKmesh => new KmeshCodec(),
        _ => null,
    };

    /// <summary>Every transport that has a codec — what the startup NIC plan iterates.</summary>
    public static IReadOnlyList<NicType> Transports { get; } =
        new[] { NicType.Mqtt4G, NicType.MqttWirepas, NicType.MqttKmesh };
}
