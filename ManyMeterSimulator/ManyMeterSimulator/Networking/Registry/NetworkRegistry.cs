using ManyMeterSimulator.Networking.Mqtt;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Networking.Registry;

/// <summary>
/// The operator-managed set of network endpoints a batch can be bound to: MQTT brokers for the RF
/// and 4G MQTT NICs, HES TCP push listeners for the 4G TCP NIC (network_registry.md §3).
///
/// <para>
/// Deliberately knows nothing about batches. <see cref="ManyMeterSimulator.Provisioning.MeterRegistry"/>
/// stores binding keys as opaque strings — exactly as it already stores a template name without
/// depending on the template registry — so the dependency runs one way only and there is no cycle.
/// The one place this registry needs to see batches is refusing to delete an endpoint still in use,
/// and that arrives through <see cref="IEndpointUsageSource"/>.
/// </para>
/// </summary>
public sealed class NetworkRegistry
{
    /// <summary>
    /// Key of the entry seeded from <c>Nics:Shared:Broker</c>. Pre-registry batches are migrated
    /// onto it, so a deployment that upgrades keeps talking to the same broker it always did.
    /// </summary>
    public const string DefaultBrokerKey = "default";

    private readonly Dictionary<string, BrokerEndpoint> _brokers = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, PushTargetEndpoint> _pushTargets = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private readonly INetworkRegistryStore _store;
    private readonly ILogger<NetworkRegistry>? _logger;

    private IEndpointUsageSource _usage = NullEndpointUsageSource.Instance;

    /// <summary>
    /// Raised after any mutation that can change which broker clients should exist. The MQTT
    /// listener subscribes so a newly added, enabled or disabled endpoint takes effect without a
    /// restart — a registry whose changes needed a restart would accept a broker that then does
    /// nothing (network_registry.md §5.5).
    /// </summary>
    public event Action? Changed;

    public NetworkRegistry(
        INetworkRegistryStore? store = null,
        IOptions<NicsOptions>? nics = null,
        ILogger<NetworkRegistry>? logger = null)
    {
        _store = store ?? NullNetworkRegistryStore.Instance;
        _logger = logger;

        LoadFromStore();
        SeedDefaultBroker(nics?.Value);
    }

    public IReadOnlyList<BrokerEndpoint> Brokers
    {
        get
        {
            lock (_lock)
            {
                return _brokers.Values.OrderBy(b => b.Key, StringComparer.OrdinalIgnoreCase).ToArray();
            }
        }
    }

    public IReadOnlyList<PushTargetEndpoint> PushTargets
    {
        get
        {
            lock (_lock)
            {
                return _pushTargets.Values.OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase).ToArray();
            }
        }
    }

    /// <summary>
    /// Supplies "which batches reference this key", used only to refuse a delete that would orphan
    /// a binding. Wired up in Program.cs once both registries exist, which is what keeps the
    /// dependency acyclic.
    /// </summary>
    public void SetUsageSource(IEndpointUsageSource usage) => _usage = usage;

    /// <summary>The broker with this key, or null. A null or unknown key means unbound (§3.2).</summary>
    public BrokerEndpoint? Broker(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return null;
        }

        lock (_lock)
        {
            return _brokers.GetValueOrDefault(key);
        }
    }

    public PushTargetEndpoint? PushTarget(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return null;
        }

        lock (_lock)
        {
            return _pushTargets.GetValueOrDefault(key);
        }
    }

    /// <summary>
    /// Adds a broker. The caller is expected to have probed it first — the registry stores what it
    /// is told, and <paramref name="verified"/> records which of the two paths the row came in on
    /// (a real connect, or the admin "save unverified" escape hatch).
    /// </summary>
    public void AddBroker(BrokerEndpoint broker, bool verified)
    {
        ValidateKey(broker.Key);

        if (string.IsNullOrWhiteSpace(broker.Host))
        {
            throw new ArgumentException("A broker needs a host.", nameof(broker));
        }

        if (broker.Port is < 1 or > 65535)
        {
            throw new ArgumentException($"Port {broker.Port} is out of range (1-65535).", nameof(broker));
        }

        lock (_lock)
        {
            RequireKeyFree(broker.Key);

            broker.Verified = verified;
            broker.LastVerifiedUtc = verified ? DateTimeOffset.UtcNow : null;
            _brokers[broker.Key] = broker;
            Persist();
        }

        _logger?.LogInformation(
            "Added broker {Broker}{Unverified}", broker.Describe(), verified ? string.Empty : " (UNVERIFIED)");
        Changed?.Invoke();
    }

    /// <summary>Adds a push target. <paramref name="verified"/> as for <see cref="AddBroker"/>.</summary>
    public void AddPushTarget(PushTargetEndpoint target, bool verified)
    {
        ValidateKey(target.Key);

        if (!PushTargetEndpoint.TryParseAddress(target.Address, out _, out string addressError))
        {
            throw new ArgumentException(addressError, nameof(target));
        }

        if (target.Port is < 1 or > 65535)
        {
            throw new ArgumentException($"Port {target.Port} is out of range (1-65535).", nameof(target));
        }

        lock (_lock)
        {
            RequireKeyFree(target.Key);

            target.Verified = verified;
            target.LastVerifiedUtc = verified ? DateTimeOffset.UtcNow : null;
            _pushTargets[target.Key] = target;
            Persist();
        }

        _logger?.LogInformation(
            "Added push target {Target}{Unverified}", target.Describe(), verified ? string.Empty : " (UNVERIFIED)");
        Changed?.Invoke();
    }

    /// <summary>
    /// Replaces a broker's connection details, keeping its key (and therefore every batch binding).
    /// Editing is how a rotated password is applied — there is no way to change a key, since that
    /// would orphan bindings with no way to detect it.
    /// </summary>
    public void UpdateBroker(BrokerEndpoint updated, bool verified)
    {
        lock (_lock)
        {
            if (!_brokers.TryGetValue(updated.Key, out BrokerEndpoint? existing))
            {
                throw new InvalidOperationException($"No broker named '{updated.Key}'.");
            }

            // Enabled is operational state, not connection detail: an edit dialog that did not
            // show the toggle would otherwise silently re-enable a deliberately disabled endpoint.
            updated.Enabled = existing.Enabled;
            updated.Verified = verified;
            updated.LastVerifiedUtc = verified ? DateTimeOffset.UtcNow : existing.LastVerifiedUtc;
            _brokers[updated.Key] = updated;
            Persist();
        }

        _logger?.LogInformation("Updated broker {Broker}", updated.Describe());
        Changed?.Invoke();
    }

    /// <summary>
    /// Turns an endpoint on or off without deleting it — the replacement for the per-transport
    /// <c>Nics:&lt;x&gt;:Enabled</c> flags (network_registry.md §5.6). A disabled broker contributes
    /// no bindings, so the reconcile pass tears its clients down.
    /// </summary>
    public bool SetBrokerEnabled(string key, bool enabled)
    {
        lock (_lock)
        {
            if (!_brokers.TryGetValue(key, out BrokerEndpoint? broker) || broker.Enabled == enabled)
            {
                return false;
            }

            broker.Enabled = enabled;
            Persist();
        }

        _logger?.LogInformation("Broker '{Key}' {State}", key, enabled ? "enabled" : "disabled");
        Changed?.Invoke();
        return true;
    }

    public bool SetPushTargetEnabled(string key, bool enabled)
    {
        lock (_lock)
        {
            if (!_pushTargets.TryGetValue(key, out PushTargetEndpoint? target) || target.Enabled == enabled)
            {
                return false;
            }

            target.Enabled = enabled;
            Persist();
        }

        _logger?.LogInformation("Push target '{Key}' {State}", key, enabled ? "enabled" : "disabled");
        Changed?.Invoke();
        return true;
    }

    /// <summary>Records the outcome of a probe or a live connection, for the health table.</summary>
    public void RecordBrokerReachable(string key, bool reachable)
    {
        lock (_lock)
        {
            if (!_brokers.TryGetValue(key, out BrokerEndpoint? broker) || !reachable)
            {
                return;
            }

            // Only success is persisted. A failure is transient health state owned by the monitor;
            // writing the file on every failed probe would rewrite the store every minute for an
            // endpoint that is simply down.
            broker.Verified = true;
            broker.LastVerifiedUtc = DateTimeOffset.UtcNow;
            Persist();
        }
    }

    public void RecordPushTargetReachable(string key, bool reachable)
    {
        lock (_lock)
        {
            if (!_pushTargets.TryGetValue(key, out PushTargetEndpoint? target) || !reachable)
            {
                return;
            }

            target.Verified = true;
            target.LastVerifiedUtc = DateTimeOffset.UtcNow;
            Persist();
        }
    }

    /// <summary>
    /// Deletes a broker, refusing while any batch is bound to it. Refusing rather than cascading:
    /// silently unbinding a batch would turn a mis-click into a fleet that answers nothing, and the
    /// operator has no way to know which batches were affected after the fact.
    /// </summary>
    public bool TryDeleteBroker(string key, out string error)
    {
        IReadOnlyList<string> users = _usage.BatchesUsingBroker(key);
        if (users.Count > 0)
        {
            error = $"'{key}' is still used by {Describe(users)}. Rebind or delete those batches first.";
            return false;
        }

        lock (_lock)
        {
            if (!_brokers.Remove(key))
            {
                error = $"No broker named '{key}'.";
                return false;
            }

            Persist();
        }

        _logger?.LogInformation("Deleted broker '{Key}'", key);
        error = string.Empty;
        Changed?.Invoke();
        return true;
    }

    public bool TryDeletePushTarget(string key, out string error)
    {
        IReadOnlyList<string> users = _usage.BatchesUsingPushTarget(key);
        if (users.Count > 0)
        {
            error = $"'{key}' is still used by {Describe(users)}. Rebind or delete those batches first.";
            return false;
        }

        lock (_lock)
        {
            if (!_pushTargets.Remove(key))
            {
                error = $"No push target named '{key}'.";
                return false;
            }

            Persist();
        }

        _logger?.LogInformation("Deleted push target '{Key}'", key);
        error = string.Empty;
        Changed?.Invoke();
        return true;
    }

    /// <summary>Whether a key is free — for live validation in the add dialog.</summary>
    public bool IsKeyAvailable(string key)
    {
        lock (_lock)
        {
            return !string.IsNullOrWhiteSpace(key)
                   && !_brokers.ContainsKey(key)
                   && !_pushTargets.ContainsKey(key);
        }
    }

    private static string Describe(IReadOnlyList<string> batches) =>
        batches.Count == 1
            ? $"batch '{batches[0]}'"
            : $"{batches.Count} batches ({string.Join(", ", batches.Take(3))}{(batches.Count > 3 ? ", …" : string.Empty)})";

    private static void ValidateKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException("An endpoint needs a name.", nameof(key));
        }

        if (key.Trim() != key)
        {
            throw new ArgumentException("An endpoint name cannot start or end with a space.", nameof(key));
        }
    }

    /// <summary>
    /// Keys are unique ACROSS both kinds, not within each. They appear together in one health
    /// table and one set of log lines, so two different endpoints named "hes-1" would be a
    /// permanent source of misreading for no benefit.
    /// </summary>
    private void RequireKeyFree(string key)
    {
        if (_brokers.ContainsKey(key) || _pushTargets.ContainsKey(key))
        {
            throw new InvalidOperationException($"An endpoint named '{key}' already exists.");
        }
    }

    private void LoadFromStore()
    {
        NetworkRegistrySnapshot snapshot = _store.Load();

        lock (_lock)
        {
            _brokers.Clear();
            _pushTargets.Clear();

            foreach (BrokerEndpoint broker in snapshot.Brokers)
            {
                _brokers[broker.Key] = broker;
            }

            foreach (PushTargetEndpoint target in snapshot.PushTargets)
            {
                _pushTargets[target.Key] = target;
            }
        }
    }

    /// <summary>
    /// Turns the legacy configured broker into a real registry row the first time this runs, so the
    /// migration in <see cref="ManyMeterSimulator.Provisioning.MeterRegistry"/> has something to
    /// bind pre-registry batches to. Does nothing once the key exists — an operator edit is never
    /// overwritten by config on the next start.
    /// </summary>
    private void SeedDefaultBroker(NicsOptions? nics)
    {
        MqttBrokerOptions? configured = nics?.Shared.Broker;
        if (configured is null || string.IsNullOrWhiteSpace(configured.Host))
        {
            return;
        }

        lock (_lock)
        {
            if (_brokers.ContainsKey(DefaultBrokerKey))
            {
                return;
            }

            MqttCredential? credential = configured.Credentials.FirstOrDefault();
            _brokers[DefaultBrokerKey] = new BrokerEndpoint
            {
                Key = DefaultBrokerKey,
                Host = configured.Host,
                Port = configured.Port,
                Username = credential?.Username ?? string.Empty,
                Password = credential?.Password ?? string.Empty,
                UseTls = configured.UseTls,
                // Unverified: it came from config, nothing has connected to it yet. The health
                // monitor promotes it on the first successful probe.
                Verified = false,
            };

            Persist();
        }

        _logger?.LogInformation(
            "Seeded broker '{Key}' from Nics:Shared:Broker ({Host}:{Port}).",
            DefaultBrokerKey, configured.Host, configured.Port);
    }

    /// <summary>Writes current state to the store. Must be called while holding <see cref="_lock"/>.</summary>
    private void Persist()
    {
        _store.Save(new NetworkRegistrySnapshot
        {
            Brokers = _brokers.Values.ToList(),
            PushTargets = _pushTargets.Values.ToList(),
        });
    }
}

/// <summary>
/// Answers "which batches are bound to this endpoint?" — the one thing
/// <see cref="NetworkRegistry"/> needs from the batch side, kept as an interface so the dependency
/// between the two registries stays one-directional.
/// </summary>
public interface IEndpointUsageSource
{
    IReadOnlyList<string> BatchesUsingBroker(string key);

    IReadOnlyList<string> BatchesUsingPushTarget(string key);
}

/// <summary>Nothing uses anything — the default until Program.cs wires the real source.</summary>
public sealed class NullEndpointUsageSource : IEndpointUsageSource
{
    public static readonly NullEndpointUsageSource Instance = new();

    private NullEndpointUsageSource()
    {
    }

    public IReadOnlyList<string> BatchesUsingBroker(string key) => Array.Empty<string>();

    public IReadOnlyList<string> BatchesUsingPushTarget(string key) => Array.Empty<string>();
}
