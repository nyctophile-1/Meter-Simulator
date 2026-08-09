using System.Collections.Concurrent;
using System.Diagnostics;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.MqttBridge;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.Models;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// Hosts one <see cref="MqttNicClient"/> per <see cref="BrokerBinding"/> — the MQTT counterpart of
/// <see cref="ManyMeterSimulator.Networking.TcpNicListenerService"/>.
///
/// <para>
/// Which clients exist is derived from the fleet, not from config: a binding exists when a RUNNING
/// batch references an ENABLED broker in the network registry. Both registries signal this service
/// when they change, so adding a broker, starting a batch or rebinding one takes effect without a
/// restart — a registry whose changes needed a restart would accept a broker that then did nothing
/// (network_registry.md §5.5).
/// </para>
///
/// <para>
/// The receive path is deliberately two-stage: the broker callback does only routing and queueing
/// (fast, no state), and everything expensive happens on the meter's own worker in
/// <see cref="NodeDispatcher"/>. Blocking the callback would stall every meter's traffic on that
/// connection, not just the one message.
/// </para>
///
/// <para>
/// The reply is published on the client the request ARRIVED on, carried through on the work item.
/// That is what gives RF and MQTT the one-to-one channel TCP gets for free from its socket, and it
/// is what makes a multi-leg DLMS exchange (AARQ → get/set → release, plus fragments) stay on one
/// broker (network_registry.md §5.2).
/// </para>
/// </summary>
public sealed class MqttNicListenerService : BackgroundService
{
    private readonly ILogger<MqttNicListenerService> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly NicsOptions _options;
    private readonly NicCaptureWriter _captures;
    private readonly MeterAdmission _admission;
    private readonly SessionRegistry _sessions;
    private readonly SimulatorMetrics _metrics;
    private readonly IMeterSimBridge _bridge;
    private readonly MeterRegistry _registry;
    private readonly NetworkRegistry _network;
    private readonly NicCodecFactory _codecs;
    private readonly ConcurrentDictionary<BrokerBinding, BoundBrokerClient> _clients = new();

    /// <summary>
    /// Released whenever something that can change the desired client set changes. A signal rather
    /// than a poll so an operator's change is visible immediately; the periodic sweep behind it is
    /// only a safety net.
    /// </summary>
    private readonly SemaphoreSlim _reconcileSignal = new(0);

    private NodeDispatcher? _dispatcher;

    public MqttNicListenerService(
        ILogger<MqttNicListenerService> logger,
        ILoggerFactory loggerFactory,
        IOptions<NicsOptions> options,
        NicCaptureWriter captures,
        MeterAdmission admission,
        SessionRegistry sessions,
        SimulatorMetrics metrics,
        IMeterSimBridge bridge,
        MeterRegistry registry,
        NetworkRegistry network,
        NicCodecFactory codecs)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
        _options = options.Value;
        _captures = captures;
        _admission = admission;
        _sessions = sessions;
        _metrics = metrics;
        _bridge = bridge;
        _registry = registry;
        _network = network;
        _codecs = codecs;
    }

    /// <summary>Per-binding broker status, for the dashboard and the Network page.</summary>
    public IReadOnlyDictionary<BrokerBinding, MqttConnectionStatus> ConnectionStatuses =>
        _clients.ToDictionary(kv => kv.Key, kv => kv.Value.Client.Status);

    /// <summary>Live status for one broker key, across every transport bound to it.</summary>
    public IReadOnlyList<(NicType Transport, MqttConnectionStatus Status)> StatusesForBroker(string brokerKey) =>
        _clients
            .Where(kv => string.Equals(kv.Key.BrokerKey, brokerKey, StringComparison.OrdinalIgnoreCase))
            .Select(kv => (kv.Key.Transport, kv.Value.Client.Status))
            .ToArray();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _dispatcher = new NodeDispatcher(
            _loggerFactory.CreateLogger("ManyMeterSimulator.Networking.Mqtt.NodeDispatcher"),
            ProcessAsync,
            _options.Shared.MailboxCapacity,
            _options.Shared.MaxConcurrentBrainCalls);

        // Print what each NIC listens to, answers on, is bound to and has provisioned, BEFORE
        // anything connects. "Nothing is happening" is the one symptom every wiring mistake here
        // shares, so the plan is logged whether or not a NIC has any bindings — an unbound batch is
        // itself the explanation.
        LogTopicPlan();

        _network.Changed += OnDependencyChanged;
        _registry.Changed += OnDependencyChanged;

        try
        {
            var interval = TimeSpan.FromSeconds(Math.Max(5, _options.Shared.ReconcileIntervalSeconds));

            while (!stoppingToken.IsCancellationRequested)
            {
                await ReconcileAsync(stoppingToken);

                // Wake on a change, or on the safety-net interval, whichever comes first.
                try
                {
                    await _reconcileSignal.WaitAsync(interval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
        finally
        {
            _network.Changed -= OnDependencyChanged;
            _registry.Changed -= OnDependencyChanged;
        }

        await ShutdownAsync();
    }

    private void OnDependencyChanged()
    {
        // Never block the mutating caller (a UI click): just poke the loop. CurrentCount is capped
        // so a burst of changes coalesces into one reconcile rather than queueing N of them.
        if (_reconcileSignal.CurrentCount == 0)
        {
            _reconcileSignal.Release();
        }
    }

    // ── Reconcile ────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Brings the live client set in line with what the fleet needs: start what is missing, stop
    /// what is no longer wanted, and restart anything whose broker details were edited underneath
    /// it.
    /// </summary>
    private async Task ReconcileAsync(CancellationToken stoppingToken)
    {
        IReadOnlyDictionary<BrokerBinding, BrokerEndpoint> desired = DesiredBindings();

        // Stop first, so a rebind that moves every batch from one broker to another does not hold
        // both connections open at once.
        foreach ((BrokerBinding binding, BoundBrokerClient client) in _clients.ToArray())
        {
            bool wanted = desired.TryGetValue(binding, out BrokerEndpoint? endpoint);

            if (wanted && client.Matches(endpoint!))
            {
                continue;
            }

            if (_clients.TryRemove(binding, out BoundBrokerClient? removed))
            {
                _logger.LogInformation(
                    "Stopping MQTT client {Binding} — {Reason}",
                    binding,
                    wanted ? "its broker's connection details changed" : "no running batch is bound to it any more");

                await removed.DisposeAsync();
            }
        }

        foreach ((BrokerBinding binding, BrokerEndpoint endpoint) in desired)
        {
            if (_clients.ContainsKey(binding) || stoppingToken.IsCancellationRequested)
            {
                continue;
            }

            StartClient(binding, endpoint, stoppingToken);
        }
    }

    /// <summary>
    /// The client set the fleet implies: one per (transport, broker) pair that a running MQTT batch
    /// references, where the broker exists and is enabled (network_registry.md §5.1).
    ///
    /// <para>
    /// A batch bound to nothing, to a deleted broker, or to a disabled one contributes no binding —
    /// its meters are simply never reached. That is a real, deliberate state, and it is reported
    /// here rather than left to be inferred from silence.
    /// </para>
    /// </summary>
    private IReadOnlyDictionary<BrokerBinding, BrokerEndpoint> DesiredBindings()
    {
        BindingPlan plan = BrokerBindingPlanner.Compute(_registry.Batches, _network.Broker);

        foreach (UnreachableBatch entry in plan.Unreachable)
        {
            // Warning, not Debug: a Running batch that nothing can reach looks exactly like a broken
            // simulator from the HES side, and this line is the only difference between the two.
            _logger.LogWarning(
                "Batch '{Batch}' ({Nic}) is Running but unreachable — {Detail}.",
                entry.Batch.Name, entry.Batch.NicType, entry.Detail);
        }

        return plan.Desired;
    }

    private void StartClient(BrokerBinding binding, BrokerEndpoint endpoint, CancellationToken stoppingToken)
    {
        INicCodec? codec = _codecs.Create(binding.Transport);
        if (codec is null)
        {
            _logger.LogWarning("{Binding}: no codec is registered for this transport; it can never answer.", binding);
            return;
        }

        MqttNicOptions variant = _options.For(binding.Transport);
        var stop = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);

        // Declared before the client so the receive callback can close over it: a message must be
        // able to name the connection it arrived on, and that is this object.
        BoundBrokerClient? bound = null;

        var client = new MqttNicClient(
            _loggerFactory.CreateLogger($"ManyMeterSimulator.Networking.Mqtt.{binding}"),
            binding.Transport,
            _options.ConnectionFor(endpoint),
            envelope => OnMessageAsync(bound!, envelope, stop.Token));

        bound = new BoundBrokerClient(binding, endpoint, client, codec, variant, stop);
        _clients[binding] = bound;

        bound.Runner = client.RunAsync(codec.RequestTopicFilters, variant.SubscribeQos, stop.Token);

        _logger.LogInformation(
            "Started MQTT client {Binding} → {Broker}; subscribed to {Filters}",
            binding, endpoint.Describe(), string.Join(", ", codec.RequestTopicFilters));
    }

    private async Task ShutdownAsync()
    {
        foreach (BoundBrokerClient client in _clients.Values)
        {
            client.RequestStop();
        }

        // Clients are stopping, so nothing new can arrive; give queued work a bounded chance to
        // finish rather than cutting meters off mid-exchange.
        if (_dispatcher is { PendingCount: > 0 })
        {
            var window = TimeSpan.FromSeconds(_options.Shared.ShutdownDrainSeconds);
            _logger.LogInformation(
                "Draining {Count} queued message(s) for up to {Seconds}s...", _dispatcher.PendingCount, window.TotalSeconds);

            bool drained = await _dispatcher.WaitForDrainAsync(window, CancellationToken.None);
            if (!drained)
            {
                _logger.LogWarning("{Count} message(s) still queued after the drain window.", _dispatcher.PendingCount);
            }
        }

        foreach (BoundBrokerClient client in _clients.Values)
        {
            await client.DisposeAsync();
        }

        _clients.Clear();
    }

    // ── Diagnostics ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Logs one block per MQTT NIC type: where its requests arrive, how a meter is identified out of
    /// them, where the answer goes, the HES-side subscription that has to match it, the framing, and
    /// which batches are provisioned for it — now including the BROKER each batch is bound to.
    ///
    /// <para>
    /// The broker column is why this survived the multi-broker change: with bindings driven by the
    /// fleet, "which broker is this batch actually going to talk to" became the most likely thing to
    /// be wrong, and it is invisible in every other log line.
    /// </para>
    ///
    /// <para>
    /// Four NIC types, three transports — IMG shares the direct-4G client, so it is annotated rather
    /// than given a client of its own. RF2 (Wirepas endpoint 13) is deliberately absent: it is a
    /// second channel on the Wirepas NIC, not a NIC, and it has no transparent-DLMS plan to print.
    /// </para>
    /// </summary>
    private void LogTopicPlan()
    {
        NicType[] mqttNics =
        {
            NicType.Mqtt4G, NicType.Mqtt4GImg, NicType.MqttWirepas, NicType.MqttKmesh,
        };

        foreach (NicType nic in mqttNics)
        {
            INicCodec? codec = _codecs.Create(nic);
            if (codec is null)
            {
                _logger.LogWarning("NIC plan {Nic}: no codec is registered for it; it can never answer.", nic);
                continue;
            }

            // Batches are matched on the NIC type the meter was provisioned as, not on the transport
            // — otherwise IMG and 4G would each report the other's meters as their own.
            List<MeterBatch> batches = _registry.Batches.Where(b => b.NicType == nic).ToList();
            string provisioned = batches.Count == 0
                ? "NONE — no batch is provisioned for this NIC, so every request would be dropped"
                : string.Join("; ", batches.Select(DescribeBatchBinding));

            NicTopicPlan plan = codec.TopicPlan;

            _logger.LogInformation(
                """
                NIC plan {Nic}{Shared}
                  listen   {Subscribe}
                  meter id {NodeIdSource}
                  publish  {Publish}
                  HES sub  {HesExpects}
                  framing  {Framing}
                  batches  {Batches}
                """,
                nic,
                nic == NicType.Mqtt4GImg ? "  [shares the Mqtt4G transport — one client, one subscription]" : string.Empty,
                plan.Subscribe,
                plan.NodeIdSource,
                plan.Publish,
                plan.HesExpects,
                plan.Framing,
                provisioned);
        }
    }

    /// <summary>One batch's line in the NIC plan, ending in what it will actually connect to.</summary>
    private string DescribeBatchBinding(MeterBatch batch)
    {
        (string first, string last) = _registry.GetNodeIdRange(batch);
        string where;

        if (string.IsNullOrWhiteSpace(batch.BrokerKey))
        {
            where = "NO BROKER — unreachable";
        }
        else if (_network.Broker(batch.BrokerKey) is not { } endpoint)
        {
            where = $"broker '{batch.BrokerKey}' MISSING from the registry — unreachable";
        }
        else if (!endpoint.Enabled)
        {
            where = $"broker '{batch.BrokerKey}' DISABLED — unreachable";
        }
        else
        {
            where = $"broker {endpoint.Describe()}";
        }

        return $"'{batch.Name}' node {first}-{last} [{batch.Status}] → {where}";
    }

    // ── Receive path ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Runs on the broker's receive callback. Route, capture, queue — nothing else.
    /// </summary>
    private Task OnMessageAsync(BoundBrokerClient source, NicEnvelope envelope, CancellationToken cancellationToken)
    {
        NicType transport = source.Binding.Transport;
        bool routed = source.Codec.TryRoute(envelope, out NicRoute route);

        if (source.Options.CaptureRawMessages)
        {
            _captures.Write(transport, envelope, routed ? route.NodeId : null);
        }

        if (!routed)
        {
            // Not addressed to a meter we simulate — Wirepas OTAP broadcasts, or a variant whose
            // decoder does not exist yet. Expected background traffic, counted separately from
            // malformed so it cannot bury a genuine decoding regression.
            _metrics.RecordIgnoredPacket(transport);
            _logger.LogDebug("{Binding}: ignoring message on {Topic} (not ours)", source.Binding, envelope.Topic);
            return Task.CompletedTask;
        }

        if (!MeterRef.TryFromNodeId(route.NodeId, transport, out MeterRef meter))
        {
            _metrics.RecordIgnoredPacket(transport);
            _logger.LogDebug("{Binding}: unusable node id '{NodeId}' on {Topic}", source.Binding, route.NodeId, envelope.Topic);
            return Task.CompletedTask;
        }

        var item = new NicWorkItem(meter, transport, source.Codec, source.Options, envelope, route, source);
        if (_dispatcher is null || !_dispatcher.TryEnqueue(item, cancellationToken))
        {
            // Back-pressure, not an error: this is what a real NIC does under a request storm.
            _metrics.RecordDroppedMailboxFull(transport);
            _logger.LogWarning("Meter {Meter}: mailbox full, dropping message on {Topic}", meter, envelope.Topic);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Runs on the meter's own worker — serialized and in order for that meter, concurrent across
    /// meters. Safe to do stateful work here.
    /// </summary>
    private async Task ProcessAsync(NicWorkItem item, CancellationToken cancellationToken)
    {
        // Unwrap first: a packet we cannot read is not evidence about the meter, so there is no
        // point opening a session for it.
        NicDecodeResult decoded = item.Codec.Decode(item.Envelope, item.Route);
        if (!decoded.IsComplete)
        {
            switch (decoded.Status)
            {
                case NicDecodeStatus.Incomplete:
                    return;   // waiting for more fragments; nothing to answer yet

                case NicDecodeStatus.Unsupported:
                    _logger.LogDebug(
                        "Meter {Meter}: {Detail} ({Topic})", item.Meter, decoded.Detail, item.Envelope.Topic);
                    return;

                default:
                    _metrics.RecordMalformedPacket(item.Transport);
                    _logger.LogWarning(
                        "Meter {Meter}: malformed packet on {Topic} — {Detail}",
                        item.Meter, item.Envelope.Topic, decoded.Detail);
                    return;
            }
        }

        WarnIfCrossBroker(item);

        if (!TryTouchOrOpenSession(item.Meter, out ConnectionState? session))
        {
            return;
        }

        session!.Touch();

        // Same funnel the TCP listener uses: hand the brain a complete wrapper frame, get one back.
        var stopwatch = Stopwatch.StartNew();
        byte[] response = await _bridge.ExchangeAsync(item.Meter, decoded.DlmsFrame!, cancellationToken);
        stopwatch.Stop();
        _metrics.RecordExchange(item.Meter.Nic, stopwatch.Elapsed);
        session.Touch();

        if (response.Length == 0)
        {
            _logger.LogDebug("Meter {Meter}: brain produced no reply for frame {FrameId}", item.Meter, decoded.FrameId);
            return;
        }

        IReadOnlyList<NicPublish> publishes =
            item.Codec.Encode(item.Envelope, item.Route, decoded.FrameId, response);

        if (publishes.Count == 0)
        {
            return;
        }

        foreach (NicPublish publish in publishes)
        {
            if (item.Options.CaptureRawMessages)
            {
                _captures.Write(item.Transport, "out", publish.Topic, item.Route.NodeId, publish.Payload);
            }

            // THE broker rule: answer on the connection the request arrived on. Looking the client
            // up by transport here would be ambiguous the moment two brokers serve one transport,
            // and a half-completed DLMS exchange split across brokers is invisible to HES — it just
            // sees an association that answers once and then goes quiet.
            await item.Source.Client.PublishAsync(publish.Topic, publish.Payload, item.Options.PublishQos, cancellationToken);

            if (item.Options.InterFragmentDelayMs > 0 && publishes.Count > 1)
            {
                await Task.Delay(item.Options.InterFragmentDelayMs, cancellationToken);
            }
        }

        // The first answer from a meter is the interesting one — it proves the whole chain works.
        // Everything after it is routine, so it drops to Debug and stays quiet at fleet scale.
        long exchanges = session.RecordExchange();
        LogLevel level = exchanges == 1 ? LogLevel.Information : LogLevel.Debug;

        _logger.Log(
            level,
            "Meter {Meter}: answered frame {FrameId} with {Bytes} DLMS bytes on {Topic} via {Binding} ({LatencyMs}ms, exchange {Count})",
            item.Meter, decoded.FrameId, response.Length, publishes[0].Topic, item.Source.Binding,
            stopwatch.Elapsed.TotalMilliseconds, exchanges);
    }

    /// <summary>
    /// Notes a request that reached us on a different broker than its batch is bound to.
    ///
    /// <para>
    /// It is still answered, on the broker it came from: real hardware replies to whoever reached
    /// it, and a request that physically arrived proves that path works whatever the registry says.
    /// Dropping it would produce the one symptom with no evidence attached. The counter is what
    /// makes a persistent misbinding visible instead of merely survivable
    /// (network_registry.md §5.3).
    /// </para>
    /// </summary>
    private void WarnIfCrossBroker(NicWorkItem item)
    {
        MeterBatch? batch = _registry.GetBatchForIndex(item.Meter.Index);
        if (batch?.BrokerKey is null
            || string.Equals(batch.BrokerKey, item.Source.Binding.BrokerKey, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        _metrics.RecordCrossBrokerMessage(item.Transport);
        _logger.LogWarning(
            "Meter {Meter} (batch '{Batch}') is bound to broker '{Bound}' but its request arrived on '{Actual}'. " +
            "Answering on '{Actual}' — check the batch's binding.",
            item.Meter, batch.Name, batch.BrokerKey, item.Source.Binding.BrokerKey, item.Source.Binding.BrokerKey);
    }

    /// <summary>
    /// Finds this meter's live session, opening one on first contact.
    ///
    /// A connectionless NIC has no accept event, so the first message IS the session start. Once
    /// open, the session is refreshed by traffic and reaped by the idle sweep — which is the only
    /// thing that ends it, since there is no close event either.
    /// </summary>
    private bool TryTouchOrOpenSession(MeterRef meter, out ConnectionState? session)
    {
        if (_sessions.TryGet(meter, out session) && session is not null)
        {
            return true;
        }

        var candidate = new ConnectionState
        {
            Meter = meter,
            SessionCts = new CancellationTokenSource(),
            IsVirtual = true,
        };

        AdmissionResult admission = _admission.TryAdmit(meter, candidate, int.MaxValue);
        if (admission.IsAdmitted)
        {
            _logger.LogInformation("Opened session for meter {Meter} (first message)", meter);
            session = candidate;
            return true;
        }

        if (admission.Outcome == AdmissionOutcome.AlreadyActive)
        {
            // Raced with another message for the same meter; the winner's session is the one to use.
            candidate.SessionCts.Dispose();
            return _sessions.TryGet(meter, out session) && session is not null;
        }

        // There is no channel to refuse on — dropping is exactly what a powered-off meter looks
        // like to the HES. The counters are already recorded by admission.
        candidate.SessionCts.Dispose();
        _logger.LogDebug("Meter {Meter}: dropped, {Reason}", meter, admission.Reason);
        session = null;
        return false;
    }

    public override void Dispose()
    {
        _reconcileSignal.Dispose();
        base.Dispose();
    }
}
