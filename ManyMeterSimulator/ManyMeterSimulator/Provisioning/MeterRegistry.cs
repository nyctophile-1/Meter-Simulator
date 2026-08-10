using System.Net;
using ManyMeterSimulator.Networking.Nic;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// Tracks meter batches - the real provisioning unit. Each batch reserves a contiguous run of
/// 1-based indices; a meter's IP address and meter serial number are both deterministic
/// functions of its index within the range (see MeterAddressing/FormatSerial), so batches never
/// overlap and each new batch simply continues from wherever the previous one left off.
///
/// Purely app-layer bookkeeping - doesn't touch OS-level routing/address assignment, which is a
/// separate, environment-specific setup step done outside the app.
/// </summary>
public sealed class MeterRegistry
{
    /// <summary>Meter serial numbers are "MY" + 9 zero-padded digits, so this is the largest supported index (one shy of a billion).</summary>
    public const long MaxIndex = 999_999_999;

    private readonly List<MeterBatch> _batches = new();
    private readonly object _lock = new();
    private readonly IBatchStore _store;
    private long _nextIndex = 1;
    private int _nextBatchId = 1;

    /// <summary>
    /// Schema version of the store as loaded. 0 means it predates the network registry and still
    /// needs <see cref="MigrateLegacyBindings"/>.
    /// </summary>
    private int _storeVersion;

    /// <summary>
    /// The store is optional so the parameterless-friendly path (unit tests) needs no persistence
    /// wiring; production supplies a <see cref="JsonBatchStore"/> via DI. On construction the
    /// registry rehydrates from the store, so batches, their status, and the allocation cursor
    /// survive restarts.
    /// </summary>
    public MeterRegistry(IBatchStore? store = null)
    {
        _store = store ?? NullBatchStore.Instance;
        LoadFromStore();
    }

    /// <summary>
    /// Raised after any mutation that can change which broker clients should exist — a batch added,
    /// started, stopped, rebound or deleted. The MQTT listener subscribes and reconciles, so a
    /// Start click takes effect immediately instead of waiting for the next sweep.
    ///
    /// <para>
    /// Always raised OUTSIDE <see cref="_lock"/>: a handler that called back into the registry
    /// while the lock was held would deadlock, and the listener's handler does exactly that when it
    /// reads <see cref="Batches"/>.
    /// </para>
    /// </summary>
    public event Action? Changed;

    public IReadOnlyList<MeterBatch> Batches
    {
        get
        {
            lock (_lock)
            {
                return _batches.ToArray();
            }
        }
    }

    /// <summary>What the next batch of the given size would reserve, without reserving anything yet.</summary>
    public BatchPreview PreviewNextBatch(string addressPrefixCidr, long count)
    {
        lock (_lock)
        {
            long start = _nextIndex;
            long end = start + count - 1;
            return new BatchPreview(
                MeterAddressing.ComputeAddress(addressPrefixCidr, start),
                MeterAddressing.ComputeAddress(addressPrefixCidr, end),
                FormatSerial(start),
                FormatSerial(end),
                MeterIdentity.NodeId(start),
                MeterIdentity.NodeId(end));
        }
    }

    /// <summary>
    /// Reserves the next `count` indices as a new batch bound to <paramref name="templateName"/>
    /// and <paramref name="nicType"/>. Does not start it. Every meter in the batch is built from
    /// that template and reachable over that NIC.
    ///
    /// Indices are allocated globally and sequentially across ALL batches regardless of NIC, so
    /// node id ranges can never overlap between batches or between NIC types.
    /// </summary>
    /// <param name="brokerKey">
    /// Network registry key of the MQTT broker this batch talks through, or null for unbound.
    /// Stored as an opaque string: this registry deliberately does not depend on
    /// <see cref="ManyMeterSimulator.Networking.Registry.NetworkRegistry"/> — exactly as it does not
    /// depend on <see cref="TemplateRegistry"/> for <paramref name="templateName"/> — which is what
    /// keeps the two registries acyclic. Existence and NIC-kind are checked by
    /// <c>NetworkBindingValidator</c> at the call site.
    /// </param>
    /// <param name="pushTargetKey">Registry key of the HES push listener, or null for unbound.</param>
    public MeterBatch AddBatch(
        string name,
        string templateName,
        long count,
        NicType nicType = NicType.Tcp4G,
        int? hesTemplateId = null,
        string? brokerKey = null,
        string? pushTargetKey = null,
        string? environmentKey = null)
    {
        if (count <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "Must provision at least one meter.");
        }

        if (string.IsNullOrWhiteSpace(templateName))
        {
            throw new ArgumentException("A batch must be bound to a template.", nameof(templateName));
        }

        MeterBatch added;
        lock (_lock)
        {
            if (_nextIndex + count - 1 > MaxIndex)
            {
                long remaining = MaxIndex - _nextIndex + 1;
                throw new InvalidOperationException(
                    $"Cannot add {count} meter(s): only {remaining} remain before the {MaxIndex} max is reached.");
            }

            var batch = new MeterBatch
            {
                Id = _nextBatchId++,
                Name = name,
                TemplateName = templateName,
                NicType = nicType,
                HesTemplateId = hesTemplateId,
                StartIndex = _nextIndex,
                Count = count,
                EnvironmentKey = Normalize(environmentKey ?? brokerKey ?? pushTargetKey),
            };
            _batches.Add(batch);
            _nextIndex += count;
            Persist();
            added = batch;
        }

        Changed?.Invoke();
        return added;
    }

    /// <summary>
    /// Rebinds a batch to different network endpoints (admin-only at the call site — rebinding
    /// redirects live traffic for every meter in the batch, so it sits with provisioning rather
    /// than with operation). Either key may be null, meaning unbound.
    ///
    /// <para>
    /// Returns true if anything actually changed, so the caller can skip a needless reconcile.
    /// </para>
    /// </summary>
    public bool SetNetworkBinding(int batchId, string? environmentKey)
    {
        lock (_lock)
        {
            MeterBatch? batch = _batches.FirstOrDefault(b => b.Id == batchId);
            if (batch is null) return false;

            string? key = Normalize(environmentKey);
            if (string.Equals(batch.EnvironmentKey, key, StringComparison.OrdinalIgnoreCase)) return false;

            batch.EnvironmentKey = key;
            Persist();
        }

        Changed?.Invoke();
        return true;
    }

    // Backward-compat overload used by existing call sites that supply separate broker/push keys.
    public bool SetNetworkBinding(int batchId, string? brokerKey, string? pushTargetKey) =>
        SetNetworkBinding(batchId, brokerKey ?? pushTargetKey);

    /// <summary>
    /// One-time migration for a store written before the network registry existed: every MQTT batch
    /// in it was, by definition, talking to the single configured broker, so it is bound to the
    /// seeded default entry rather than silently becoming unbound (network_registry.md §3.2).
    ///
    /// <para>
    /// Called once at startup from Program.cs, where both registries exist — that is what lets this
    /// registry stay independent of the network one. The schema version is bumped whether or not
    /// anything was bound, so this decision is made exactly once: without that, an operator who
    /// later created a deliberately-unbound batch and then added a broker named "default" would
    /// find it silently bound on the next restart.
    /// </para>
    /// </summary>
    /// <param name="defaultBrokerKey">
    /// The seeded broker to bind to, or null when none exists (nothing is bound, but the store is
    /// still marked migrated).
    /// </param>
    /// <returns>How many batches were bound.</returns>
    public int MigrateLegacyBindings(string? defaultBrokerKey)
    {
        lock (_lock)
        {
            if (_storeVersion >= BatchStoreSnapshot.CurrentVersion)
            {
                return 0;
            }

            int bound = 0;
            if (!string.IsNullOrWhiteSpace(defaultBrokerKey))
            {
                foreach (MeterBatch batch in _batches)
                {
                    if (NicTypes.IsMqtt(batch.NicType) && batch.EnvironmentKey is null)
                    {
                        batch.EnvironmentKey = defaultBrokerKey;
                        bound++;
                    }
                }
            }

            _storeVersion = BatchStoreSnapshot.CurrentVersion;
            Persist();
            return bound;
        }
    }

    public IReadOnlyList<string> BatchesUsingEnvironment(string key)
    {
        lock (_lock)
        {
            return _batches
                .Where(b => string.Equals(b.EnvironmentKey, key, StringComparison.OrdinalIgnoreCase))
                .Select(b => b.Name)
                .ToArray();
        }
    }

    // Backward-compat aliases.
    public IReadOnlyList<string> BatchesUsingBroker(string key) => BatchesUsingEnvironment(key);
    public IReadOnlyList<string> BatchesUsingPushTarget(string key) => BatchesUsingEnvironment(key);

    public bool TryStart(int batchId) => TrySetStatus(batchId, BatchStatus.Running);

    public bool TryMarkStarting(int batchId) => TrySetStatus(batchId, BatchStatus.Starting);

    public bool TryStop(int batchId) => TrySetStatus(batchId, BatchStatus.Stopped);

    public bool Delete(int batchId)
    {
        bool removed;
        lock (_lock)
        {
            removed = _batches.RemoveAll(b => b.Id == batchId) > 0;
            if (removed)
            {
                // Note: _nextIndex is intentionally NOT rolled back — the deleted range is retired,
                // not reclaimed, so a future batch never reissues those addresses.
                Persist();
            }
        }

        if (removed)
        {
            Changed?.Invoke();
        }

        return removed;
    }

    /// <summary>
    /// Removes every batch and rewinds the allocation cursor so provisioning starts from index 1
    /// again — a clean slate ("start from scratch"). Persisted like any other mutation, so the empty
    /// state survives a restart. Does NOT touch live brain sessions — the caller clears those.
    /// </summary>
    public void Reset()
    {
        lock (_lock)
        {
            _batches.Clear();
            _nextIndex = 1;
            _nextBatchId = 1;
            Persist();
        }

        Changed?.Invoke();
    }

    /// <summary>The IP address, meter serial for every index in a batch. Lazy - caller controls how many are enumerated/rendered.</summary>
    public IEnumerable<(long Index, IPAddress Address, string Serial)> GetMeters(MeterBatch batch, string addressPrefixCidr)
    {
        for (long i = batch.StartIndex; i <= batch.EndIndex; i++)
        {
            yield return (i, MeterAddressing.ComputeAddress(addressPrefixCidr, i), FormatSerial(i));
        }
    }

    /// <summary>
    /// First/last address of a batch's own range - O(1), doesn't enumerate the whole batch.
    /// Only meaningful for <see cref="NicType.Tcp4G"/> batches; the MQTT NICs are reached by node id.
    /// </summary>
    public (IPAddress First, IPAddress Last) GetAddressRange(MeterBatch batch, string addressPrefixCidr) =>
        (MeterAddressing.ComputeAddress(addressPrefixCidr, batch.StartIndex),
         MeterAddressing.ComputeAddress(addressPrefixCidr, batch.EndIndex));

    /// <summary>
    /// First/last node id of a batch's own range. Present for EVERY NIC — the HES registers a meter
    /// by node id whatever its transport, so this is the range an operator hands over after
    /// provisioning. O(1).
    /// </summary>
    public (string First, string Last) GetNodeIdRange(MeterBatch batch) =>
        (MeterIdentity.NodeId(batch.StartIndex), MeterIdentity.NodeId(batch.EndIndex));

    /// <summary>
    /// The batch that owns this meter index, or null if the index isn't part of any batch. The
    /// index is the NIC-agnostic identity, so this is the lookup every NIC uses; the address
    /// overload below is the TCP/UI convenience on top of it.
    /// </summary>
    public MeterBatch? GetBatchForIndex(long index)
    {
        lock (_lock)
        {
            foreach (MeterBatch batch in _batches)
            {
                if (index >= batch.StartIndex && index <= batch.EndIndex)
                {
                    return batch;
                }
            }
        }

        return null;
    }

    /// <summary>The batch that owns this address, or null if the address isn't part of any batch.</summary>
    public MeterBatch? GetBatchForAddress(IPAddress address) =>
        GetBatchForIndex(MeterAddressing.ExtractIndex(address));

    /// <summary>Status of the batch that owns this address, or null if the address isn't part of any batch.</summary>
    public BatchStatus? GetBatchStatusForAddress(IPAddress address, string addressPrefixCidr) =>
        GetBatchForAddress(address)?.Status;

    /// <summary>Template name of the batch that owns this address, or null if unprovisioned.</summary>
    public string? GetTemplateNameForAddress(IPAddress address) =>
        GetBatchForAddress(address)?.TemplateName;

    private bool TrySetStatus(int batchId, BatchStatus status)
    {
        lock (_lock)
        {
            MeterBatch? batch = _batches.FirstOrDefault(b => b.Id == batchId);
            if (batch is null)
            {
                return false;
            }

            batch.Status = status;
            Persist();
        }

        // Start/Stop changes which broker clients should exist, so the listener reconciles now
        // rather than on its next sweep.
        Changed?.Invoke();
        return true;
    }

    /// <summary>Rebuilds the in-memory state from the store. Called once, from the constructor.</summary>
    private void LoadFromStore()
    {
        BatchStoreSnapshot snapshot = _store.Load();

        lock (_lock)
        {
            _batches.Clear();
            foreach (PersistedBatch pb in snapshot.Batches)
            {
                _batches.Add(new MeterBatch
                {
                    Id = pb.Id,
                    Name = pb.Name,
                    TemplateName = pb.TemplateName,
                    NicType = pb.NicType,
                    HesTemplateId = pb.HesTemplateId,
                    StartIndex = pb.StartIndex,
                    Count = pb.Count,
                    Status = pb.Status,
                    EnvironmentKey = pb.EnvironmentKey ?? pb.BrokerKey ?? pb.PushTargetKey,
                    CreatedAtUtc = pb.CreatedAtUtc,
                });
            }

            _nextIndex = snapshot.NextIndex;
            _nextBatchId = snapshot.NextBatchId;
            _storeVersion = snapshot.Version;
        }
    }

    /// <summary>
    /// The current state as a portable snapshot — the exact shape written to <c>batches.json</c>,
    /// carrying no secrets (a batch holds only identity and registry KEYS, never credentials). This
    /// is what the export button serializes, so a fleet — the painful part, since every meter is
    /// registered with the HES — can be moved to another deployment intact.
    /// </summary>
    public BatchStoreSnapshot Snapshot()
    {
        lock (_lock)
        {
            return BuildSnapshot();
        }
    }

    /// <summary>
    /// Replaces every batch and both cursors with an imported snapshot. Wholesale, not a merge:
    /// merging two independently-allocated index spaces is exactly how a batch would reissue an
    /// address the HES already knows, which is the collision this store exists to prevent. The
    /// caller confirms first (it discards the current fleet) and clears live sessions after.
    /// </summary>
    public void ImportSnapshot(BatchStoreSnapshot snapshot)
    {
        lock (_lock)
        {
            _batches.Clear();
            foreach (PersistedBatch pb in snapshot.Batches)
            {
                _batches.Add(new MeterBatch
                {
                    Id = pb.Id,
                    Name = pb.Name,
                    TemplateName = pb.TemplateName,
                    NicType = pb.NicType,
                    HesTemplateId = pb.HesTemplateId,
                    StartIndex = pb.StartIndex,
                    Count = pb.Count,
                    Status = pb.Status,
                    EnvironmentKey = pb.EnvironmentKey ?? pb.BrokerKey ?? pb.PushTargetKey,
                    CreatedAtUtc = pb.CreatedAtUtc,
                });
            }

            // A hand-written cursor below the max batch id/index would reissue ids; trust the
            // batches over the snapshot's own cursor fields, which a hand-edit could leave stale.
            _nextIndex = Math.Max(snapshot.NextIndex, _batches.Count == 0 ? 1 : _batches.Max(b => b.EndIndex) + 1);
            _nextBatchId = Math.Max(snapshot.NextBatchId, _batches.Count == 0 ? 1 : _batches.Max(b => b.Id) + 1);
            // Imported files are already in the current schema; do not re-run the legacy migration.
            _storeVersion = BatchStoreSnapshot.CurrentVersion;
            Persist();
        }

        Changed?.Invoke();
    }

    /// <summary>Writes the current state to the store. Must be called while holding <see cref="_lock"/>.</summary>
    private void Persist() => _store.Save(BuildSnapshot());

    /// <summary>Builds a snapshot of current state. Caller must hold <see cref="_lock"/>.</summary>
    private BatchStoreSnapshot BuildSnapshot() => new()
    {
        Version = _storeVersion,
        NextIndex = _nextIndex,
        NextBatchId = _nextBatchId,
        Batches = _batches.Select(b => new PersistedBatch
        {
            Id = b.Id,
            Name = b.Name,
            TemplateName = b.TemplateName,
            NicType = b.NicType,
            HesTemplateId = b.HesTemplateId,
            StartIndex = b.StartIndex,
            Count = b.Count,
            Status = b.Status,
            EnvironmentKey = b.EnvironmentKey,
            CreatedAtUtc = b.CreatedAtUtc,
        }).ToList(),
    };

    /// <summary>
    /// Collapses "", whitespace and null into null, so unbound is ONE state rather than three that
    /// compare differently against a registry key.
    /// </summary>
    private static string? Normalize(string? key) =>
        string.IsNullOrWhiteSpace(key) ? null : key.Trim();

    public static string FormatSerial(long index) => $"MY{index:D9}";
}

public readonly record struct BatchPreview(
    IPAddress FirstAddress,
    IPAddress LastAddress,
    string FirstSerial,
    string LastSerial,
    string FirstNodeId,
    string LastNodeId);
