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
    public bool Validate(NicType nic, string? environmentKey, out string error)
    {
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(environmentKey)) return true;

        var env = _network.Environment(environmentKey);
        if (env is null)
        {
            error = $"No environment named '{environmentKey}' exists in the network registry.";
            return false;
        }

        if (NicTypes.IsMqtt(nic) && !env.HasBroker)
        {
            error = $"Environment '{environmentKey}' has no MQTT broker configured.";
            return false;
        }

        return true;
    }

    // Backward-compat overload used by existing call sites.
    public bool Validate(NicType nic, string? brokerKey, string? pushTargetKey, out string error) =>
        Validate(nic, brokerKey ?? pushTargetKey, out error);

    public static bool IsUnreachable(MeterBatch batch) =>
        NicTypes.IsMqtt(batch.NicType)
        && batch.Status == BatchStatus.Running
        && string.IsNullOrWhiteSpace(batch.EnvironmentKey);

    public IReadOnlyList<string> BatchesUsingEnvironment(string key) => _batches.BatchesUsingEnvironment(key);
}
