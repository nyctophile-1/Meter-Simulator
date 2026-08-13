using System.Collections.Concurrent;
using System.Net;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Brain;

/// <summary>
/// The authoritative per-meter runtime store — the single source of truth for every live
/// meter's DLMS state, keyed by the meter's stable index (see <see cref="MeterRef"/>), so the
/// same meter resolves to the same session whichever NIC its traffic arrived on.
///
/// This is NOT a cache: a session is built ONCE from the meter's batch template on first touch
/// and is then the meter's live, mutable object model. It is never rebuilt from the template on
/// reconnect (that would wipe mutations and desync what the HES pulls from what a meter would
/// push), and it is not evicted while the process runs. Both the inbound pull path
/// (<see cref="BrainMeterSimBridge"/>) and the future outbound push path resolve the same
/// instance here, which is what makes "pushed and pulled data belong to the same meter" true.
///
/// Scale note: state is in-RAM for now (test scale). Field scale (millions) will back this with
/// a persistence/paging store (SQLite) behind this same seam — nothing else holds meter state.
/// </summary>
public sealed class MeterSessionManager
{
    private readonly MeterRegistry _meterRegistry;
    private readonly TemplateRegistry _templates;
    private readonly BrainOptions _options;
    private readonly TcpOptions _tcpOptions;
    private readonly ILogger<MeterSessionManager> _logger;

    // Lazy so each meter's session is constructed exactly once even under concurrent first-touch.
    private readonly ConcurrentDictionary<long, Lazy<DLMSServerSession>> _sessions = new();
    private readonly ConcurrentDictionary<int, BatchMaterializationProgress> _startingProgress = new();

    public event Action<BatchMaterializationProgress>? OnProgressChanged;

    public MeterSessionManager(
        MeterRegistry meterRegistry,
        TemplateRegistry templates,
        IOptions<BrainOptions> options,
        IOptions<TcpOptions> tcpOptions,
        ILogger<MeterSessionManager> logger)
    {
        _meterRegistry = meterRegistry;
        _templates = templates;
        _options = options.Value;
        _tcpOptions = tcpOptions.Value;
        _logger = logger;
    }

    /// <summary>Number of meters with a live session.</summary>
    public int LiveMeterCount => _sessions.Count;

    /// <summary>Gets active materialization progress for a batch being started, or null if not starting.</summary>
    public BatchMaterializationProgress? GetProgress(int batchId) =>
        _startingProgress.TryGetValue(batchId, out var p) ? p : null;

    /// <summary>
    /// Drops every live meter session. Used by the admin "reset batches" flow so a fresh batch that
    /// reuses an address (numbering restarts at 1) doesn't resolve a stale, previously-built session.
    /// In-flight connections keep the instance they already resolved; new ones rebuild from template.
    /// </summary>
    public void Clear() => _sessions.Clear();

    /// <summary>
    /// Returns the authoritative session for a meter, building it once on first touch.
    /// Throws if the meter belongs to no batch or its template can't be resolved — callers on
    /// the inbound path should already have rejected such connections (see the listener's
    /// no-template gate).
    /// </summary>
    public DLMSServerSession GetOrCreate(MeterRef meter)
    {
        Lazy<DLMSServerSession> lazy = _sessions.GetOrAdd(
            meter.Index,
            _ => new Lazy<DLMSServerSession>(() => Build(meter), LazyThreadSafetyMode.ExecutionAndPublication));

        try
        {
            return lazy.Value;
        }
        catch
        {
            // Don't cache a failed build — a later attempt (e.g. after the template is fixed) should retry.
            _sessions.TryRemove(meter.Index, out _);
            throw;
        }
    }

    private DLMSServerSession Build(MeterRef meterRef)
    {
        MeterBatch batch = _meterRegistry.GetBatchForIndex(meterRef.Index)
            ?? throw new InvalidOperationException($"Meter {meterRef} belongs to no batch (no template).");

        string templatePath = _templates.ResolveOrThrow(batch.TemplateName);

        var meter = new DLMSMeter(meterRef.Index, _options.LogicalName, _options.ClientAddress, _options.ServerAddress);

        // For TCP meters the source address of an outbound push MUST be the meter's own IPv6 (the
        // same address HES pulls from) so the receiver correlates the push by source IP. MQTT meters
        // have no per-meter IP, so no source binding. The periodic-timer PushConfig stays null —
        // push is on-demand (the dashboard "Send Push" button drives DLMSServerSession.PushNow).
        IPAddress? sourceAddress = meterRef.Nic == NicType.Tcp4G
            ? MeterAddressing.ComputeAddress(_tcpOptions.AddressPrefix, meterRef.Index)
            : null;

        var session = new DLMSServerSession(meter, templatePath, pushConfig: null, sourceAddress: sourceAddress);
        session.Initialize(true);

        _logger.LogDebug(
            "Built meter session {Meter} (index {Index}, serial {Serial}, template {Template})",
            meterRef, meterRef.Index, meter.MeterNo, batch.TemplateName);

        return session;
    }

    /// <summary>
    /// Starts a batch asynchronously: marks status as Starting, materializes all meter sessions in
    /// background chunks without blocking the UI thread, and sets status to Running upon completion.
    /// </summary>
    public async Task StartBatchAsync(int batchId, CancellationToken cancellationToken = default)
    {
        MeterBatch? batch = _meterRegistry.Batches.FirstOrDefault(b => b.Id == batchId);
        if (batch is null) return;

        _meterRegistry.TryMarkStarting(batchId);
        long total = batch.EndIndex - batch.StartIndex + 1;
        var initialProgress = new BatchMaterializationProgress(batch.Id, 0, total);
        _startingProgress[batch.Id] = initialProgress;
        OnProgressChanged?.Invoke(initialProgress);

        await Task.Yield();

        try
        {
            await MaterializeBatchAsync(batch, cancellationToken: cancellationToken);
            _meterRegistry.TryStart(batchId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start batch {BatchId} ({BatchName})", batchId, batch.Name);
            _meterRegistry.TryStop(batchId);
            throw;
        }
        finally
        {
            _startingProgress.TryRemove(batchId, out _);
            var finalProgress = new BatchMaterializationProgress(batch.Id, total, total);
            OnProgressChanged?.Invoke(finalProgress);
        }
    }

    /// <summary>
    /// Asynchronously materializes every meter in a batch in chunks of 500 meters, yielding execution
    /// to keep the UI thread fully responsive.
    /// </summary>
    public async Task<IReadOnlyList<(MeterRef Meter, DLMSServerSession Session)>> MaterializeBatchAsync(
        MeterBatch batch,
        IProgress<BatchMaterializationProgress>? progress = null,
        CancellationToken cancellationToken = default,
        int? maximumMeters = null)
    {
        var result = new List<(MeterRef, DLMSServerSession)>();
        long total = Math.Min(batch.EndIndex - batch.StartIndex + 1, Math.Max(0, maximumMeters ?? int.MaxValue));
        long count = 0;
        int chunkSize = 500;

        await Task.Yield();

        for (long index = batch.StartIndex; count < total; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var meter = new MeterRef(index, batch.NicType);
            result.Add((meter, GetOrCreate(meter)));
            count++;

            if (count % chunkSize == 0 || count == total)
            {
                var p = new BatchMaterializationProgress(batch.Id, count, total);
                _startingProgress[batch.Id] = p;
                progress?.Report(p);
                OnProgressChanged?.Invoke(p);
                await Task.Yield();
            }
        }

        _logger.LogDebug("Materialized {Count} meter session(s) for batch {BatchId} ({BatchName})",
            result.Count, batch.Id, batch.Name);

        return result;
    }

    /// <summary>Synchronous wrapper for backwards compatibility.</summary>
    public IReadOnlyList<(MeterRef Meter, DLMSServerSession Session)> MaterializeBatch(MeterBatch batch)
    {
        return MaterializeBatchAsync(batch).GetAwaiter().GetResult();
    }
}

public record BatchMaterializationProgress(int BatchId, long MaterializedCount, long TotalCount)
{
    public double Percent => TotalCount > 0 ? (MaterializedCount * 100.0 / TotalCount) : 0;
    public bool IsComplete => MaterializedCount >= TotalCount;
}
