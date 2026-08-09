using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Networking.Registry;

/// <summary>
/// Checks that a batch's network binding makes sense before it is stored, and answers "which
/// batches use this endpoint?" for the registry's delete guard.
///
/// <para>
/// This is where the two registries meet, and it exists so that neither has to know about the
/// other. <see cref="MeterRegistry"/> stores binding keys as opaque strings (exactly as it stores a
/// template name without depending on <see cref="TemplateRegistry"/>), and
/// <see cref="NetworkRegistry"/> reaches the batch side only through
/// <see cref="IEndpointUsageSource"/> — so the dependency graph stays acyclic with the validator as
/// the single point that sees both.
/// </para>
/// </summary>
public sealed class NetworkBindingValidator : IEndpointUsageSource
{
    private readonly NetworkRegistry _network;
    private readonly MeterRegistry _batches;

    public NetworkBindingValidator(NetworkRegistry network, MeterRegistry batches)
    {
        _network = network;
        _batches = batches;
    }

    /// <summary>
    /// Validates a proposed binding for a batch of the given NIC.
    ///
    /// <para>
    /// Null is always valid: unbound is a deliberate state, not a missing value
    /// (network_registry.md §3.2). What is rejected is a key that does not resolve, or one of the
    /// wrong kind for the NIC — a broker on a TCP batch, or a push target on an MQTT batch. Both
    /// would be stored happily and then do nothing, which is the failure this whole feature exists
    /// to stop being invisible.
    /// </para>
    /// </summary>
    public bool Validate(NicType nic, string? brokerKey, string? pushTargetKey, out string error)
    {
        error = string.Empty;

        if (!string.IsNullOrWhiteSpace(brokerKey))
        {
            if (!NicTypes.IsMqtt(nic))
            {
                error = $"A {nic} batch has no broker — inbound TCP is broker-agnostic. Leave it unbound.";
                return false;
            }

            if (_network.Broker(brokerKey) is null)
            {
                error = $"No broker named '{brokerKey}' exists in the network registry.";
                return false;
            }
        }

        if (!string.IsNullOrWhiteSpace(pushTargetKey))
        {
            if (nic != NicType.Tcp4G)
            {
                // MQTT meters have no per-meter source IP for a receiver to correlate on, which is
                // why PushCoordinator already refuses them.
                error = $"Push targets apply to 4G TCP batches only, not {nic}.";
                return false;
            }

            if (_network.PushTarget(pushTargetKey) is null)
            {
                error = $"No push target named '{pushTargetKey}' exists in the network registry.";
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Whether this batch is a running MQTT batch that is bound to nothing — the one silent
    /// failure mode of an unbound binding, surfaced wherever batches are listed.
    /// </summary>
    public static bool IsUnreachable(MeterBatch batch) =>
        NicTypes.IsMqtt(batch.NicType)
        && batch.Status == BatchStatus.Running
        && string.IsNullOrWhiteSpace(batch.BrokerKey);

    public IReadOnlyList<string> BatchesUsingBroker(string key) => _batches.BatchesUsingBroker(key);

    public IReadOnlyList<string> BatchesUsingPushTarget(string key) => _batches.BatchesUsingPushTarget(key);
}
