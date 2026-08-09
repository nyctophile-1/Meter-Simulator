using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// Works out which broker clients the fleet needs, and — just as importantly — which batches will
/// be reached by nothing.
///
/// <para>
/// Pure and separate from <see cref="MqttNicListenerService"/> so the rule can be tested directly.
/// This is the decision that replaced the old <c>Nics:&lt;x&gt;:Enabled</c> config flags, and
/// getting it wrong is silent in both directions: a missing binding means a batch nobody can reach,
/// and a spurious one means a connection to a broker nobody asked for.
/// </para>
/// </summary>
public static class BrokerBindingPlanner
{
    /// <summary>
    /// A binding exists when a RUNNING MQTT batch references a broker that is present and enabled.
    /// Everything else is reported as unreachable with the reason, so silence is never the only
    /// symptom (network_registry.md §5.1).
    /// </summary>
    /// <param name="lookup">Resolves a broker key, or null when it is not in the registry.</param>
    public static BindingPlan Compute(IEnumerable<MeterBatch> batches, Func<string, BrokerEndpoint?> lookup)
    {
        var desired = new Dictionary<BrokerBinding, BrokerEndpoint>();
        var unreachable = new List<UnreachableBatch>();

        foreach (MeterBatch batch in batches)
        {
            if (!NicTypes.IsMqtt(batch.NicType) || batch.Status != BatchStatus.Running)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(batch.BrokerKey))
            {
                unreachable.Add(new UnreachableBatch(
                    batch, UnreachableReason.Unbound, "bound to no broker — bind it on the Network page"));
                continue;
            }

            BrokerEndpoint? endpoint = lookup(batch.BrokerKey);
            if (endpoint is null)
            {
                unreachable.Add(new UnreachableBatch(
                    batch, UnreachableReason.MissingBroker, $"broker '{batch.BrokerKey}' is not in the network registry"));
                continue;
            }

            if (!endpoint.Enabled)
            {
                unreachable.Add(new UnreachableBatch(
                    batch, UnreachableReason.DisabledBroker, $"broker '{batch.BrokerKey}' is disabled"));
                continue;
            }

            // Keyed on the TRANSPORT, so a 4G and a 4G IMG batch on the same broker share one
            // client and one subscription — nothing on the wire distinguishes them, and two clients
            // would deliver every message twice.
            desired[new BrokerBinding(NicTypes.TransportFor(batch.NicType), endpoint.Key)] = endpoint;
        }

        return new BindingPlan(desired, unreachable);
    }
}

/// <summary>What should be running, and what will be heard by nobody.</summary>
public sealed record BindingPlan(
    IReadOnlyDictionary<BrokerBinding, BrokerEndpoint> Desired,
    IReadOnlyList<UnreachableBatch> Unreachable);

public sealed record UnreachableBatch(MeterBatch Batch, UnreachableReason Reason, string Detail);

public enum UnreachableReason
{
    /// <summary>Deliberately bound to nothing — legal, but worth saying out loud for a running batch.</summary>
    Unbound,

    /// <summary>Bound to a key that is not in the registry (deleted, or a hand-edited store).</summary>
    MissingBroker,

    /// <summary>Bound to a broker an operator has switched off.</summary>
    DisabledBroker,
}
