namespace ManyMeterSimulator.Networking.Registry;

/// <summary>
/// Durable backing for <see cref="NetworkRegistry"/>. Mirrors
/// <see cref="ManyMeterSimulator.Provisioning.IBatchStore"/> deliberately: the registry loads a
/// snapshot on construction and saves one after every mutation.
///
/// <para>
/// It shares the BATCH store's failure policy, not the runtime-config store's. Losing these rows
/// silently would leave batches bound to keys that no longer resolve — meters that answer nothing,
/// with no error anywhere. That is the same class of damage as losing the allocation cursor, so a
/// corrupt file is fatal rather than falling back to empty (network_registry.md §3.4).
/// </para>
/// </summary>
public interface INetworkRegistryStore
{
    NetworkRegistrySnapshot Load();

    void Save(NetworkRegistrySnapshot snapshot);
}

/// <summary>
/// The whole registry as one serializable document. Passwords inside are ciphertext — the store
/// protects on save and unprotects on load, so nothing above <see cref="INetworkRegistryStore"/>
/// ever handles an encrypted value.
/// </summary>
public sealed record NetworkRegistrySnapshot
{
    /// <summary>
    /// 1 = legacy separate brokers+pushTargets; 2 = unified environments.
    /// Bumped when migration logic is needed on load.
    /// </summary>
    public int Version { get; init; } = 2;

    /// <summary>Current format: unified HES environments (version ≥ 2).</summary>
    public List<HesEnvironment> Environments { get; init; } = new();

    /// <summary>Legacy brokers (version 1). Read on load for migration only; never written.</summary>
    public List<BrokerEndpoint> Brokers { get; init; } = new();

    /// <summary>Legacy push targets (version 1). Read on load for migration only; never written.</summary>
    public List<PushTargetEndpoint> PushTargets { get; init; } = new();
}

/// <summary>
/// No-op store for unit tests and any deployment that opts out of persistence — the counterpart of
/// <see cref="ManyMeterSimulator.Provisioning.NullBatchStore"/>.
/// </summary>
public sealed class NullNetworkRegistryStore : INetworkRegistryStore
{
    public static readonly NullNetworkRegistryStore Instance = new();

    private NullNetworkRegistryStore()
    {
    }

    public NetworkRegistrySnapshot Load() => new();

    public void Save(NetworkRegistrySnapshot snapshot)
    {
    }
}
