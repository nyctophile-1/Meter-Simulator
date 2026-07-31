using System.Net;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Networking.Nic;

/// <summary>
/// Identifies one simulated meter to every layer below the NIC — admission, session registry and
/// the brain funnel all take this instead of an <see cref="IPAddress"/>.
///
/// The meter INDEX is the canonical identity: the brain builds a meter from it, and the serial,
/// node id and (for TCP) the IPv6 address are all deterministic functions of it. Each NIC derives
/// its own transport address from the same number, which is what makes "one brain, many NICs" work
/// without the brain ever learning what a topic or a socket is.
///
/// Deliberately keyed on the integer rather than the node-id string: a string key would fork a
/// meter's state into two sessions the moment a codec emitted "001005" once and "1005" another
/// time. <see cref="NodeId"/> keeps every contract, log line and UI surface string-facing, and the
/// two can never drift because one is computed from the other.
/// </summary>
public readonly record struct MeterRef(long Index, NicType Nic)
{
    /// <summary>The HES-facing node id — universal, present on every NIC including TCP.</summary>
    public string NodeId => MeterIdentity.NodeId(Index);

    /// <summary>The meter serial ("MY" + 9 digits), the identity carried inside the DLMS payload.</summary>
    public string Serial => MeterIdentity.Serial(Index);

    /// <summary>
    /// Resolves the meter a TCP connection belongs to. The kernel routes the whole meter prefix to
    /// this host, so the socket's LOCAL address is the meter's own address and carries its index.
    /// </summary>
    public static MeterRef FromTcpAddress(IPAddress meterAddress) =>
        new(MeterAddressing.ExtractIndex(meterAddress), NicType.Tcp4G);

    /// <summary>
    /// Resolves the meter a node id refers to, for the MQTT NICs. Tolerates zero-padding, since a
    /// topic or protobuf field may carry a fixed-width id. False if it is not a usable node id.
    /// </summary>
    public static bool TryFromNodeId(string? nodeId, NicType nic, out MeterRef meter)
    {
        if (long.TryParse(nodeId, out long index) && index > 0)
        {
            meter = new MeterRef(index, nic);
            return true;
        }

        meter = default;
        return false;
    }

    public override string ToString() => $"{Nic}/{NodeId}";
}
