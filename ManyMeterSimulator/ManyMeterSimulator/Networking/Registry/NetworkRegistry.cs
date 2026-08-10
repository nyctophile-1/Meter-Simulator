using ManyMeterSimulator.Networking.Mqtt;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Networking.Registry;

/// <summary>
/// The operator-managed set of HES environments a batch can be bound to. An environment pairs a
/// TCP push listener with an MQTT broker — one HES instance, one registry row.
///
/// <para>
/// Deliberately knows nothing about batches. <see cref="ManyMeterSimulator.Provisioning.MeterRegistry"/>
/// stores binding keys as opaque strings — exactly as it does for template names — so the dependency
/// runs one way only and there is no cycle. The one place this registry needs to see batches is
/// refusing to delete an environment still in use, and that arrives through
/// <see cref="IEndpointUsageSource"/>.
/// </para>
/// </summary>
public sealed class NetworkRegistry
{
    /// <summary>
    /// Key of the environment seeded from <c>Nics:Shared:Broker</c>. Pre-registry batches are
    /// migrated onto it so a deployment that upgrades keeps talking to the same broker it always did.
    /// </summary>
    public const string DefaultBrokerKey = "default";

    private readonly Dictionary<string, HesEnvironment> _environments = new(StringComparer.OrdinalIgnoreCase);
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

    public IReadOnlyList<HesEnvironment> Environments
    {
        get
        {
            lock (_lock)
            {
                return _environments.Values.OrderBy(e => e.Key, StringComparer.OrdinalIgnoreCase).ToArray();
            }
        }
    }

    // ── Backward-compat views (used by existing MQTT/push infrastructure) ──────────────────────

    /// <summary>All environments that have a broker configured, as <see cref="BrokerEndpoint"/> adapters.</summary>
    public IReadOnlyList<BrokerEndpoint> Brokers
    {
        get
        {
            lock (_lock)
            {
                return _environments.Values
                    .Where(e => e.HasBroker)
                    .OrderBy(e => e.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(e => e.AsBrokerEndpoint())
                    .ToArray();
            }
        }
    }

    /// <summary>All environments that have TCP configured, as <see cref="PushTargetEndpoint"/> adapters.</summary>
    public IReadOnlyList<PushTargetEndpoint> PushTargets
    {
        get
        {
            lock (_lock)
            {
                return _environments.Values
                    .Where(e => e.HasTcp)
                    .OrderBy(e => e.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(e => e.AsPushTargetEndpoint())
                    .ToArray();
            }
        }
    }

    /// <summary>
    /// Supplies "which batches reference this key", used only to refuse a delete that would orphan
    /// a binding. Wired up in Program.cs once both registries exist, which is what keeps the
    /// dependency acyclic.
    /// </summary>
    public void SetUsageSource(IEndpointUsageSource usage) => _usage = usage;

    /// <summary>The environment with this key, or null.</summary>
    public HesEnvironment? Environment(string? key)
    {
        if (string.IsNullOrWhiteSpace(key)) return null;
        lock (_lock) { return _environments.GetValueOrDefault(key); }
    }

    /// <summary>Broker adapter for <paramref name="key"/> — used by MQTT infrastructure.</summary>
    public BrokerEndpoint? Broker(string? key)
    {
        if (string.IsNullOrWhiteSpace(key)) return null;
        lock (_lock)
        {
            return _environments.TryGetValue(key, out HesEnvironment? env) && env.HasBroker
                ? env.AsBrokerEndpoint()
                : null;
        }
    }

    /// <summary>Push-target adapter for <paramref name="key"/> — used by PushCoordinator.</summary>
    public PushTargetEndpoint? PushTarget(string? key)
    {
        if (string.IsNullOrWhiteSpace(key)) return null;
        lock (_lock)
        {
            return _environments.TryGetValue(key, out HesEnvironment? env) && env.HasTcp
                ? env.AsPushTargetEndpoint()
                : null;
        }
    }

    // ── Mutations ──────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Adds a new HES environment. The caller is expected to have probed it first;
    /// <paramref name="verified"/> records which path the row came in on.
    /// </summary>
    public void AddEnvironment(HesEnvironment env, bool verified)
    {
        ValidateKey(env.Key);

        lock (_lock)
        {
            if (_environments.ContainsKey(env.Key))
            {
                throw new InvalidOperationException($"An environment named '{env.Key}' already exists.");
            }

            env.Verified = verified;
            env.LastVerifiedUtc = verified ? DateTimeOffset.UtcNow : null;
            _environments[env.Key] = env;
            Persist();
        }

        _logger?.LogInformation(
            "Added environment {Env}{Unverified}", env.Describe(), verified ? string.Empty : " (UNVERIFIED)");
        Changed?.Invoke();
    }

    /// <summary>
    /// Replaces connection details for an existing environment, keeping its key and therefore every
    /// batch binding. Enabled is preserved — an edit dialog that does not show the toggle must not
    /// silently re-enable a deliberately disabled environment.
    /// </summary>
    public void UpdateEnvironment(HesEnvironment updated, bool verified)
    {
        lock (_lock)
        {
            if (!_environments.TryGetValue(updated.Key, out HesEnvironment? existing))
            {
                throw new InvalidOperationException($"No environment named '{updated.Key}'.");
            }

            updated.Enabled = existing.Enabled;
            updated.Verified = verified;
            updated.LastVerifiedUtc = verified ? DateTimeOffset.UtcNow : existing.LastVerifiedUtc;
            _environments[updated.Key] = updated;
            Persist();
        }

        _logger?.LogInformation("Updated environment {Env}", updated.Describe());
        Changed?.Invoke();
    }

    public bool SetEnvironmentEnabled(string key, bool enabled)
    {
        lock (_lock)
        {
            if (!_environments.TryGetValue(key, out HesEnvironment? env) || env.Enabled == enabled)
            {
                return false;
            }

            env.Enabled = enabled;
            Persist();
        }

        _logger?.LogInformation("Environment '{Key}' {State}", key, enabled ? "enabled" : "disabled");
        Changed?.Invoke();
        return true;
    }

    /// <summary>Records a successful probe so the health column shows the last-seen time.</summary>
    public void RecordEnvironmentReachable(string key)
    {
        lock (_lock)
        {
            if (!_environments.TryGetValue(key, out HesEnvironment? env)) return;
            env.Verified = true;
            env.LastVerifiedUtc = DateTimeOffset.UtcNow;
            Persist();
        }
    }

    public bool TryDeleteEnvironment(string key, out string error)
    {
        IReadOnlyList<string> users = _usage.BatchesUsingEnvironment(key);
        if (users.Count > 0)
        {
            error = $"'{key}' is still used by {DescribeBatches(users)}. Rebind or delete those batches first.";
            return false;
        }

        lock (_lock)
        {
            if (!_environments.Remove(key))
            {
                error = $"No environment named '{key}'.";
                return false;
            }

            Persist();
        }

        _logger?.LogInformation("Deleted environment '{Key}'", key);
        error = string.Empty;
        Changed?.Invoke();
        return true;
    }

    // ── Backward-compat mutation wrappers (used by tests and legacy call sites) ─────────────────

    /// <summary>Creates or updates the broker half of the matching environment.</summary>
    public void AddBroker(BrokerEndpoint broker, bool verified)
    {
        ValidateKey(broker.Key);
        lock (_lock)
        {
            if (!_environments.TryGetValue(broker.Key, out HesEnvironment? env))
            {
                env = new HesEnvironment { Key = broker.Key };
                _environments[broker.Key] = env;
            }

            env.BrokerHost = broker.Host;
            env.BrokerPort = broker.Port;
            env.BrokerUsername = broker.Username;
            env.BrokerPassword = broker.Password;
            env.BrokerUseTls = broker.UseTls;
            env.Enabled = broker.Enabled;
            env.Verified = verified;
            env.LastVerifiedUtc = verified ? DateTimeOffset.UtcNow : null;
            Persist();
        }

        _logger?.LogInformation(
            "Added broker {Broker}{Unverified}", broker.Describe(), verified ? string.Empty : " (UNVERIFIED)");
        Changed?.Invoke();
    }

    /// <summary>Creates or updates the TCP half of the matching environment.</summary>
    public void AddPushTarget(PushTargetEndpoint target, bool verified)
    {
        ValidateKey(target.Key);

        if (!PushTargetEndpoint.TryParseAddress(target.Address, out _, out string addressError))
            throw new ArgumentException(addressError, nameof(target));

        lock (_lock)
        {
            if (!_environments.TryGetValue(target.Key, out HesEnvironment? env))
            {
                env = new HesEnvironment { Key = target.Key };
                _environments[target.Key] = env;
            }

            env.TcpHost = target.Address;
            env.TcpPort = target.Port;
            env.Verified = verified;
            env.LastVerifiedUtc = verified ? DateTimeOffset.UtcNow : null;
            Persist();
        }

        _logger?.LogInformation(
            "Added push target {Target}{Unverified}", target.Describe(), verified ? string.Empty : " (UNVERIFIED)");
        Changed?.Invoke();
    }

    public void UpdateBroker(BrokerEndpoint updated, bool verified)
    {
        lock (_lock)
        {
            if (!_environments.TryGetValue(updated.Key, out HesEnvironment? env))
                throw new InvalidOperationException($"No environment named '{updated.Key}'.");

            env.BrokerHost = updated.Host;
            env.BrokerPort = updated.Port;
            env.BrokerUsername = updated.Username;
            env.BrokerPassword = updated.Password;
            env.BrokerUseTls = updated.UseTls;
            env.Verified = verified;
            env.LastVerifiedUtc = verified ? DateTimeOffset.UtcNow : env.LastVerifiedUtc;
            Persist();
        }

        _logger?.LogInformation("Updated broker {Broker}", updated.Describe());
        Changed?.Invoke();
    }

    public bool SetBrokerEnabled(string key, bool enabled) => SetEnvironmentEnabled(key, enabled);

    public bool SetPushTargetEnabled(string key, bool enabled) => SetEnvironmentEnabled(key, enabled);

    public void RecordBrokerReachable(string key, bool reachable)
    {
        if (reachable) RecordEnvironmentReachable(key);
    }

    public void RecordPushTargetReachable(string key, bool reachable)
    {
        if (reachable) RecordEnvironmentReachable(key);
    }

    public bool TryDeleteBroker(string key, out string error) => TryDeleteEnvironment(key, out error);

    public bool TryDeletePushTarget(string key, out string error) => TryDeleteEnvironment(key, out error);

    /// <summary>Whether a key is free — for live validation in the add dialog.</summary>
    public bool IsKeyAvailable(string key)
    {
        lock (_lock)
        {
            return !string.IsNullOrWhiteSpace(key) && !_environments.ContainsKey(key);
        }
    }

    // ── Snapshot / persistence ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Current state as a portable snapshot, with broker passwords in <b>plaintext</b>.
    /// The exported file carries real credentials — the UI states this plainly before export.
    /// </summary>
    public NetworkRegistrySnapshot Snapshot()
    {
        lock (_lock)
        {
            return new NetworkRegistrySnapshot { Environments = _environments.Values.ToList() };
        }
    }

    /// <summary>
    /// Replaces every environment with an imported snapshot, then persists (re-encrypting passwords
    /// under this host's key ring). Wholesale — a half-applied config would leave bindings pointing
    /// at environments that are not there.
    /// </summary>
    public void ImportSnapshot(NetworkRegistrySnapshot snapshot)
    {
        lock (_lock)
        {
            _environments.Clear();

            // Prefer the new unified format; fall back to migrating legacy broker+push lists.
            if (snapshot.Environments.Count > 0)
            {
                foreach (HesEnvironment env in snapshot.Environments)
                {
                    _environments[env.Key] = env;
                }
            }
            else
            {
                MigrateLegacySnapshot(snapshot);
            }

            Persist();
        }

        Changed?.Invoke();
    }

    private void LoadFromStore()
    {
        NetworkRegistrySnapshot snapshot = _store.Load();

        lock (_lock)
        {
            _environments.Clear();

            if (snapshot.Environments.Count > 0)
            {
                foreach (HesEnvironment env in snapshot.Environments)
                {
                    _environments[env.Key] = env;
                }
            }
            else if (snapshot.Brokers.Count > 0 || snapshot.PushTargets.Count > 0)
            {
                MigrateLegacySnapshot(snapshot);
                Persist(); // write the migrated data in the new format immediately
            }
        }
    }

    /// <summary>
    /// Pairs legacy broker and push-target rows by key into unified environments. Rows whose key
    /// exists in both lists are merged; unpaired rows become environments with only one half set.
    /// </summary>
    private void MigrateLegacySnapshot(NetworkRegistrySnapshot snapshot)
    {
        foreach (BrokerEndpoint broker in snapshot.Brokers)
        {
            if (!_environments.TryGetValue(broker.Key, out HesEnvironment? env))
            {
                env = new HesEnvironment { Key = broker.Key, CreatedAtUtc = broker.CreatedAtUtc };
                _environments[broker.Key] = env;
            }

            env.BrokerHost = broker.Host;
            env.BrokerPort = broker.Port;
            env.BrokerUsername = broker.Username;
            env.BrokerPassword = broker.Password;
            env.BrokerUseTls = broker.UseTls;
            env.Enabled = broker.Enabled;
            env.Verified = broker.Verified;
            env.LastVerifiedUtc = broker.LastVerifiedUtc;
        }

        foreach (PushTargetEndpoint target in snapshot.PushTargets)
        {
            if (!_environments.TryGetValue(target.Key, out HesEnvironment? env))
            {
                env = new HesEnvironment { Key = target.Key, CreatedAtUtc = target.CreatedAtUtc };
                _environments[target.Key] = env;
            }

            env.TcpHost = target.Address;
            env.TcpPort = target.Port;
            if (!env.Verified && target.Verified)
            {
                env.Verified = true;
                env.LastVerifiedUtc = target.LastVerifiedUtc;
            }
        }

        if (_environments.Count > 0)
        {
            _logger?.LogInformation(
                "Migrated {Count} legacy broker/push-target row(s) to HES environments.", _environments.Count);
        }
    }

    /// <summary>
    /// Turns the legacy configured broker into a registry environment the first time this runs, so
    /// the migration in MeterRegistry has something to bind pre-registry batches to.
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
            if (_environments.ContainsKey(DefaultBrokerKey))
            {
                return;
            }

            MqttCredential? credential = configured.Credentials.FirstOrDefault();
            _environments[DefaultBrokerKey] = new HesEnvironment
            {
                Key = DefaultBrokerKey,
                BrokerHost = configured.Host,
                BrokerPort = configured.Port,
                BrokerUsername = credential?.Username ?? string.Empty,
                BrokerPassword = credential?.Password ?? string.Empty,
                BrokerUseTls = configured.UseTls,
                Verified = false,
            };

            Persist();
        }

        _logger?.LogInformation(
            "Seeded environment '{Key}' from Nics:Shared:Broker ({Host}:{Port}).",
            DefaultBrokerKey, configured.Host, configured.Port);
    }

    private void Persist()
    {
        _store.Save(new NetworkRegistrySnapshot
        {
            Environments = _environments.Values.ToList(),
        });
    }

    private static string DescribeBatches(IReadOnlyList<string> batches) =>
        batches.Count == 1
            ? $"batch '{batches[0]}'"
            : $"{batches.Count} batches ({string.Join(", ", batches.Take(3))}{(batches.Count > 3 ? ", …" : string.Empty)})";

    private static void ValidateKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
            throw new ArgumentException("An environment needs a name.", nameof(key));

        if (key.Trim() != key)
            throw new ArgumentException("An environment name cannot start or end with a space.", nameof(key));
    }
}

/// <summary>
/// Answers "which batches are bound to this environment?" — the one thing
/// <see cref="NetworkRegistry"/> needs from the batch side, kept as an interface so the dependency
/// between the two registries stays one-directional.
/// </summary>
public interface IEndpointUsageSource
{
    IReadOnlyList<string> BatchesUsingEnvironment(string key);

    // Backward-compat aliases — both delegate to BatchesUsingEnvironment since an environment key
    // is now the single binding identifier for both the broker and TCP push halves.
    IReadOnlyList<string> BatchesUsingBroker(string key) => BatchesUsingEnvironment(key);

    IReadOnlyList<string> BatchesUsingPushTarget(string key) => BatchesUsingEnvironment(key);
}

/// <summary>Nothing uses anything — the default until Program.cs wires the real source.</summary>
public sealed class NullEndpointUsageSource : IEndpointUsageSource
{
    public static readonly NullEndpointUsageSource Instance = new();

    private NullEndpointUsageSource()
    {
    }

    public IReadOnlyList<string> BatchesUsingEnvironment(string key) => Array.Empty<string>();
}
