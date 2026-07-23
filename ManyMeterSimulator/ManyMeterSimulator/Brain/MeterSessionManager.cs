using System.Collections.Concurrent;
using System.Net;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Brain;

/// <summary>
/// The authoritative per-meter runtime store — the single source of truth for every live
/// meter's DLMS state, keyed by the meter's stable IPv6 address.
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
    private readonly ILogger<MeterSessionManager> _logger;

    // Lazy so each meter's session is constructed exactly once even under concurrent first-touch.
    private readonly ConcurrentDictionary<IPAddress, Lazy<DLMSServerSession>> _sessions = new();

    public MeterSessionManager(
        MeterRegistry meterRegistry,
        TemplateRegistry templates,
        IOptions<BrainOptions> options,
        ILogger<MeterSessionManager> logger)
    {
        _meterRegistry = meterRegistry;
        _templates = templates;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>Number of meters with a live session.</summary>
    public int LiveMeterCount => _sessions.Count;

    /// <summary>
    /// Returns the authoritative session for a meter, building it once on first touch.
    /// Throws if the meter belongs to no batch or its template can't be resolved — callers on
    /// the inbound path should already have rejected such connections (see the listener's
    /// no-template gate).
    /// </summary>
    public DLMSServerSession GetOrCreate(IPAddress meterId)
    {
        Lazy<DLMSServerSession> lazy = _sessions.GetOrAdd(
            meterId,
            id => new Lazy<DLMSServerSession>(() => Build(id), LazyThreadSafetyMode.ExecutionAndPublication));

        try
        {
            return lazy.Value;
        }
        catch
        {
            // Don't cache a failed build — a later attempt (e.g. after the template is fixed) should retry.
            _sessions.TryRemove(meterId, out _);
            throw;
        }
    }

    private DLMSServerSession Build(IPAddress meterId)
    {
        MeterBatch batch = _meterRegistry.GetBatchForAddress(meterId)
            ?? throw new InvalidOperationException($"Meter {meterId} belongs to no batch (no template).");

        string templatePath = _templates.ResolveOrThrow(batch.TemplateName);
        long index = MeterAddressing.ExtractIndex(meterId);

        var meter = new DLMSMeter(index, _options.LogicalName, _options.ClientAddress, _options.ServerAddress);

        // Push is deferred: pushConfig null → no push timer is wired (see merge_task.md #12/#15).
        var session = new DLMSServerSession(meter, templatePath, pushConfig: null);
        session.Initialize(true);

        _logger.LogInformation(
            "Built meter session {MeterId} (index {Index}, serial {Serial}, template {Template})",
            meterId, index, meter.MeterNo, batch.TemplateName);

        return session;
    }

    // ── Push-readiness seam (merge_task.md #15) — intentionally NOT implemented in this phase ──
    /// <summary>
    /// Eagerly materialize every meter in a batch so they are "live" WITHOUT an inbound HES
    /// connection — required by the future push scheduler, since a Started batch must push on its
    /// own schedule regardless of whether HES is polling. Deferred; the seam exists so adding push
    /// later needs no change to the inbound path.
    /// </summary>
    public void MaterializeBatch(int batchId) =>
        throw new NotImplementedException(
            "Push-readiness seam: eager batch materialization is deferred (see merge_task.md #15).");
}
