namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// Durable backing for <see cref="MeterRegistry"/>. The registry loads a snapshot on construction
/// and saves one after every mutation, so batches, their status, and — critically — the allocation
/// cursor (which prevents IP/serial reuse) survive process restarts and redeployments.
/// </summary>
public interface IBatchStore
{
    /// <summary>Reads the persisted snapshot, or an empty one if nothing has been stored yet.</summary>
    BatchStoreSnapshot Load();

    /// <summary>Overwrites the persisted snapshot with the given state.</summary>
    void Save(BatchStoreSnapshot snapshot);
}

/// <summary>
/// A complete, serialization-friendly picture of the registry: the two monotonic cursors plus one
/// row per batch. Deliberately a separate DTO from <see cref="MeterBatch"/> (which has required/
/// init-only members and a computed range) so the on-disk shape can evolve independently.
/// </summary>
public sealed record BatchStoreSnapshot
{
    public long NextIndex { get; init; } = 1;

    public int NextBatchId { get; init; } = 1;

    public List<PersistedBatch> Batches { get; init; } = new();
}

/// <summary>One persisted batch row. Mirrors the durable fields of <see cref="MeterBatch"/>.</summary>
public sealed record PersistedBatch
{
    public int Id { get; init; }

    public string Name { get; init; } = string.Empty;

    public string TemplateName { get; init; } = string.Empty;

    public long StartIndex { get; init; }

    public long Count { get; init; }

    public BatchStatus Status { get; init; }

    public DateTimeOffset CreatedAtUtc { get; init; }
}

/// <summary>
/// No-op store: <see cref="Load"/> returns an empty snapshot and <see cref="Save"/> does nothing.
/// The default when <see cref="MeterRegistry"/> is constructed without a store (unit tests, or a
/// deployment that deliberately opts out of persistence).
/// </summary>
public sealed class NullBatchStore : IBatchStore
{
    public static readonly NullBatchStore Instance = new();

    private NullBatchStore()
    {
    }

    public BatchStoreSnapshot Load() => new();

    public void Save(BatchStoreSnapshot snapshot)
    {
    }
}
