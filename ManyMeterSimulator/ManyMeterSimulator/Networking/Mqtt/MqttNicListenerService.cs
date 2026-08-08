using System.Collections.Concurrent;
using System.Diagnostics;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.MqttBridge;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.Models;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// Hosts one <see cref="MqttNicClient"/> per enabled MQTT transport — the MQTT counterpart of
/// <see cref="ManyMeterSimulator.Networking.TcpNicListenerService"/>.
///
/// The receive path is deliberately two-stage: the broker callback does only routing and queueing
/// (fast, no state), and everything expensive happens on the meter's own worker in
/// <see cref="NodeDispatcher"/>. Blocking the callback would stall every meter's traffic on that
/// connection, not just the one message.
///
/// <para>
/// Phase D scope: route → dispatch → admission → virtual session. The unwrap/brain/wrap/publish
/// steps land in Phase E, once the codecs can produce a correctly framed reply.
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
    private readonly IReadOnlyDictionary<NicType, INicCodec> _codecs;
    private readonly ConcurrentDictionary<NicType, MqttNicClient> _clients = new();

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
        IEnumerable<INicCodec> codecs)
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
        _codecs = codecs.ToDictionary(c => c.Nic);
    }

    /// <summary>Per-transport broker status, for the dashboard.</summary>
    public IReadOnlyDictionary<NicType, MqttConnectionStatus> ConnectionStatuses =>
        _clients.ToDictionary(kv => kv.Key, kv => kv.Value.Status);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        NicType[] enabled = _options.EnabledTransports().ToArray();

        // Before anything connects: print what each NIC listens to, answers on, and has provisioned.
        // "Nothing is happening" is the one symptom every wiring mistake here shares, so the plan is
        // logged whether or not a transport is enabled — a disabled NIC is itself an explanation.
        LogTopicPlan(enabled);

        if (enabled.Length == 0)
        {
            _logger.LogInformation("No MQTT NICs are enabled; the MQTT listener is idle.");
            return;
        }

        _dispatcher = new NodeDispatcher(
            _loggerFactory.CreateLogger("ManyMeterSimulator.Networking.Mqtt.NodeDispatcher"),
            ProcessAsync,
            _options.Shared.MailboxCapacity,
            _options.Shared.MaxConcurrentBrainCalls);

        var runners = new List<Task>();
        foreach (NicType transport in enabled)
        {
            if (!_codecs.TryGetValue(transport, out INicCodec? codec))
            {
                _logger.LogWarning("{Nic} is enabled but has no codec registered; skipping.", transport);
                continue;
            }

            MqttBrokerOptions broker = _options.BrokerFor(transport);
            if (string.IsNullOrWhiteSpace(broker.Host))
            {
                _logger.LogWarning(
                    "{Nic} is enabled but no broker host is configured (set Nics:Shared:Broker:Host); skipping.", transport);
                continue;
            }

            MqttNicOptions variant = _options.For(transport);
            var client = new MqttNicClient(
                _loggerFactory.CreateLogger($"ManyMeterSimulator.Networking.Mqtt.{transport}"),
                transport,
                broker,
                envelope => OnMessageAsync(transport, codec, variant, envelope, stoppingToken));

            _clients[transport] = client;
            runners.Add(client.RunAsync(codec.RequestTopicFilters, variant.SubscribeQos, stoppingToken));
        }

        if (runners.Count == 0)
        {
            return;
        }

        _logger.LogInformation(
            "MQTT NIC listener started for {Count} transport(s): {Nics}",
            runners.Count, string.Join(", ", _clients.Keys));

        await Task.WhenAll(runners);

        // Clients have stopped, so nothing new can arrive; give queued work a bounded chance to
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

        foreach (MqttNicClient client in _clients.Values)
        {
            await client.DisposeAsync();
        }
    }

    /// <summary>
    /// Logs one block per MQTT NIC type: where its requests arrive, how a meter is identified out of
    /// them, where the answer goes, the HES-side subscription that has to match it, the framing, and
    /// which batches are actually provisioned for it.
    ///
    /// <para>
    /// Four NIC types, three transports — IMG shares the direct-4G client, so it is annotated rather
    /// than given a client of its own. RF2 (Wirepas endpoint 13) is deliberately absent: it is a
    /// second channel on the Wirepas NIC, not a NIC, and it has no transparent-DLMS plan to print.
    /// </para>
    /// </summary>
    private void LogTopicPlan(IReadOnlyCollection<NicType> enabledTransports)
    {
        NicType[] mqttNics =
        {
            NicType.Mqtt4G, NicType.Mqtt4GImg, NicType.MqttWirepas, NicType.MqttKmesh,
        };

        foreach (NicType nic in mqttNics)
        {
            NicType transport = NicTypes.TransportFor(nic);

            if (!_codecs.TryGetValue(transport, out INicCodec? codec))
            {
                _logger.LogWarning("NIC plan {Nic}: no codec is registered for it; it can never answer.", nic);
                continue;
            }

            // Batches are matched on the NIC type the meter was provisioned as, not on the transport
            // — otherwise IMG and 4G would each report the other's meters as their own.
            List<MeterBatch> batches = _registry.Batches.Where(b => b.NicType == nic).ToList();
            string provisioned = batches.Count == 0
                ? "NONE — no batch is provisioned for this NIC, so every request would be dropped"
                : string.Join("; ", batches.Select(b =>
                {
                    (string first, string last) = _registry.GetNodeIdRange(b);
                    return $"'{b.Name}' node {first}-{last} [{b.Status}]";
                }));

            NicTopicPlan plan = codec.TopicPlan;

            _logger.LogInformation(
                """
                NIC plan {Nic} — {State}{Shared}
                  listen   {Subscribe}
                  meter id {NodeIdSource}
                  publish  {Publish}
                  HES sub  {HesExpects}
                  framing  {Framing}
                  batches  {Batches}
                """,
                nic,
                enabledTransports.Contains(transport) ? "ENABLED" : "DISABLED (set Nics:" + transport + ":Enabled=true)",
                nic == NicType.Mqtt4GImg ? "  [shares the Mqtt4G transport — one client, one subscription]" : string.Empty,
                plan.Subscribe,
                plan.NodeIdSource,
                plan.Publish,
                plan.HesExpects,
                plan.Framing,
                provisioned);
        }
    }

    /// <summary>
    /// Runs on the broker's receive callback. Route, capture, queue — nothing else.
    /// </summary>
    private Task OnMessageAsync(
        NicType transport, INicCodec codec, MqttNicOptions variant, NicEnvelope envelope, CancellationToken cancellationToken)
    {
        bool routed = codec.TryRoute(envelope, out NicRoute route);

        if (variant.CaptureRawMessages)
        {
            _captures.Write(transport, envelope, routed ? route.NodeId : null);
        }

        if (!routed)
        {
            // Not addressed to a meter we simulate — Wirepas OTAP broadcasts, or a variant whose
            // decoder does not exist yet. Expected background traffic, counted separately from
            // malformed so it cannot bury a genuine decoding regression.
            _metrics.RecordIgnoredPacket(transport);
            _logger.LogDebug("{Nic}: ignoring message on {Topic} (not ours)", transport, envelope.Topic);
            return Task.CompletedTask;
        }

        if (!MeterRef.TryFromNodeId(route.NodeId, transport, out MeterRef meter))
        {
            _metrics.RecordIgnoredPacket(transport);
            _logger.LogDebug("{Nic}: unusable node id '{NodeId}' on {Topic}", transport, route.NodeId, envelope.Topic);
            return Task.CompletedTask;
        }

        var item = new NicWorkItem(meter, transport, codec, variant, envelope, route);
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

        if (publishes.Count == 0 || !_clients.TryGetValue(item.Transport, out MqttNicClient? client))
        {
            return;
        }

        foreach (NicPublish publish in publishes)
        {
            if (item.Options.CaptureRawMessages)
            {
                _captures.Write(item.Transport, "out", publish.Topic, item.Route.NodeId, publish.Payload);
            }

            await client.PublishAsync(publish.Topic, publish.Payload, item.Options.PublishQos, cancellationToken);

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
            "Meter {Meter}: answered frame {FrameId} with {Bytes} DLMS bytes on {Topic} ({LatencyMs}ms, exchange {Count})",
            item.Meter, decoded.FrameId, response.Length, publishes[0].Topic,
            stopwatch.Elapsed.TotalMilliseconds, exchanges);
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
}
