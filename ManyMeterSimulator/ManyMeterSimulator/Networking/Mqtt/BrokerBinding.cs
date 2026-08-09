using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// One MQTT client's identity: a transport plus the registry key of the broker it dials.
///
/// <para>
/// This replaced <see cref="NicType"/> as the key of the client dictionary, and that swap is the
/// whole of multi-broker support. With one client per transport there was exactly one place a reply
/// could go, so two brokers serving the same transport had no way to be told apart; with this,
/// every client is addressable and a reply can be sent back to the connection its request arrived
/// on (network_registry.md §5.1).
/// </para>
///
/// <para>
/// Note it is the TRANSPORT, not the NIC: 4G and 4G IMG on the same broker are one binding, one
/// client and one subscription, because they are indistinguishable on the wire. Giving them
/// separate clients would deliver every message twice.
/// </para>
/// </summary>
public readonly record struct BrokerBinding(NicType Transport, string BrokerKey)
{
    /// <summary>Compact form for logs and dictionary keys in the UI, e.g. <c>Mqtt4G@pune</c>.</summary>
    public override string ToString() => $"{Transport}@{BrokerKey}";
}
