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
    /// <summary>Bumped only if a future change needs migration logic; unread today.</summary>
    public int Version { get; init; } = 1;

    public List<BrokerEndpoint> Brokers { get; init; } = new();

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
