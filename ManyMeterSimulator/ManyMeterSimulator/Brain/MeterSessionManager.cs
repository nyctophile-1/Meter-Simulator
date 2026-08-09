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
    /// Eagerly materializes every meter in a batch so they are "live" WITHOUT an inbound HES
    /// connection, returning each meter paired with its session. The push path needs this because a
    /// meter with no prior HES pull has no session yet — there'd be nothing to push from. Building a
    /// session is the same idempotent first-touch as the inbound path (<see cref="GetOrCreate"/>), so
    /// calling this for a batch already being polled just returns the existing instances.
    /// </summary>
    public IReadOnlyList<(MeterRef Meter, DLMSServerSession Session)> MaterializeBatch(MeterBatch batch)
    {
        var result = new List<(MeterRef, DLMSServerSession)>();
        for (long index = batch.StartIndex; index <= batch.EndIndex; index++)
        {
            var meter = new MeterRef(index, batch.NicType);
            result.Add((meter, GetOrCreate(meter)));
        }

        _logger.LogDebug("Materialized {Count} meter session(s) for batch {BatchId} ({BatchName})",
            result.Count, batch.Id, batch.Name);

        return result;
    }
}
