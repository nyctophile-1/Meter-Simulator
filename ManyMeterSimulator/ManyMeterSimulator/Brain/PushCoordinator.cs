using System.Diagnostics;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Brain;

/// <summary>
/// Drives the dashboard "Send Push" button: materializes a whole batch and fires one on-demand push
/// per meter to the operator-supplied destination. Orchestration only — the DLMS/encoding and the
/// outbound socket live in <see cref="DLMSServerSession"/>; per-meter state lives in
/// <see cref="MeterSessionManager"/>. Nothing here knows what a DataNotification frame looks like.
/// </summary>
public sealed class PushCoordinator
{
    private readonly MeterRegistry _registry;
    private readonly MeterSessionManager _sessions;
    private readonly NetworkRegistry _network;
    private readonly TcpPushSender _tcpPush;
    private readonly IMqttPushPublisher _mqtt;
    private readonly NicCodecFactory _codecs;
    private readonly PushOptions _options;
    private readonly SimulatorMetrics _metrics;
    private readonly ILogger<PushCoordinator> _logger;

    public PushCoordinator(
        MeterRegistry registry,
        MeterSessionManager sessions,
        NetworkRegistry network,
        TcpPushSender tcpPush,
        IMqttPushPublisher mqtt,
        NicCodecFactory codecs,
        IOptions<PushOptions> options,
        SimulatorMetrics metrics,
        ILogger<PushCoordinator> logger)
    {
        _registry = registry;
        _sessions = sessions;
        _network = network;
        _tcpPush = tcpPush;
        _mqtt = mqtt;
        _codecs = codecs;
        _options = options.Value;
        _metrics = metrics;
        _logger = logger;
    }

    /// <summary>The port applied to a bare-IP destination, and the ciphering/default the UI shows.</summary>
    public PushOptions Options => _options;

    /// <summary>
    /// Pushes every meter in a batch. The destination is the batch's bound push target from the
    /// network registry; <paramref name="destination"/> overrides it when supplied ("ip", "ip:port",
    /// or "[ipv6]:port").
    ///
    /// <para>
    /// The override exists because the dashboard box is the bring-up tool — type an address, prove
    /// the path, then bind it properly — and that button is expected to be hidden once push is
    /// scheduled. The binding is what a scheduled push will read, so it is the default, not the
    /// afterthought.
    /// </para>
    ///
    /// <para>
    /// Meters are materialized first so a never-polled batch can still push. Sends run concurrently
    /// up to <see cref="PushOptions.MaxConcurrency"/>; each meter's push is serialized against its
    /// own session lock so it can't collide with an in-flight HES pull.
    /// </para>
    /// </summary>
    public async Task<PushBatchResult> PushBatchAsync(
        int batchId, string? destination = null, CancellationToken cancellationToken = default, int? maximumMeters = null,
        bool selectRandomly = false)
    {
        MeterBatch? batch = _registry.Batches.FirstOrDefault(b => b.Id == batchId);
        if (batch is null)
        {
            return PushBatchResult.ForError($"Batch {batchId} no longer exists.");
        }

        // "The correct channel": a TCP batch pushes over a socket to its bound IP; an MQTT batch
        // publishes to its bound broker. The one Send-Push button dispatches on the batch's NIC.
        return batch.NicType == NicType.Tcp4G
            ? await PushTcpAsync(batch, destination, cancellationToken, maximumMeters, selectRandomly)
            : await PushMqttAsync(batch, cancellationToken, maximumMeters, selectRandomly);
    }

    /// <summary>
    /// TCP push: each meter opens a socket from its own IP to the HES push listener (the source IP
    /// is how HES tells the meters apart — see <see cref="TcpPushSender"/>).
    /// </summary>
    private async Task<PushBatchResult> PushTcpAsync(
        MeterBatch batch, string? destination, CancellationToken cancellationToken, int? maximumMeters, bool selectRandomly)
    {
        if (!TryResolveDestination(batch, destination, out string resolved, out string error))
        {
            return PushBatchResult.ForError(error);
        }

        destination = resolved;

        IReadOnlyList<(MeterRef Meter, DLMSServerSession Session)> meters = await _sessions.MaterializeBatchAsync(batch, cancellationToken: cancellationToken, maximumMeters: maximumMeters, selectRandomly: selectRandomly);

        int metersSent = 0, metersFailed = 0;
        using var gate = new SemaphoreSlim(Math.Max(1, _options.MaxConcurrency));

        var tasks = meters.Select(async pair =>
        {
            await gate.WaitAsync(cancellationToken);
            long startedTicks = Stopwatch.GetTimestamp();
            try
            {
                // Two stages, cleanly split: the session ENCODES the push (transport-agnostic), and
                // the NIC sender puts it on the wire. Encoding stays on Task.Run — it is CPU work
                // under the same monitor the inbound bridge takes, so it can block on a meter that
                // is mid-pull. The send does NOT: it is async all the way down now, so thousands of
                // pushes can be in flight without a thread each.
                byte[][] payloads = await Task.Run(() =>
                {
                    lock (pair.Session)
                    {
                        return pair.Session.BuildPushPayloads(_options.UseCiphering).ToArray();
                    }
                }, cancellationToken);

                if (payloads.Length == 0)
                {
                    _metrics.RecordPushSkipped(batch.NicType);
                    return;   // meter has no sendable PushSetup — not counted either way
                }

                PushDeliveryResult result = await _tcpPush.SendAsync(
                    pair.Meter.Serial, pair.Session.SourceAddress, destination,
                    _options.DefaultPort, payloads, cancellationToken);

                _metrics.RecordPushPayloads(batch.NicType, result.Sent, result.Failed);

                if (result.Failed == 0 && result.Sent > 0)
                {
                    Interlocked.Increment(ref metersSent);
                    _metrics.RecordPushMeter(batch.NicType, ok: true, Stopwatch.GetElapsedTime(startedTicks));
                }
                else if (result.Sent > 0 || result.Failed > 0)
                {
                    // Fully or partially failed — count the meter as failed.
                    Interlocked.Increment(ref metersFailed);
                    _metrics.RecordPushMeter(batch.NicType, ok: false, Stopwatch.GetElapsedTime(startedTicks));
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Push failed for meter {Meter}", pair.Meter);
                Interlocked.Increment(ref metersFailed);
                _metrics.RecordPushMeter(batch.NicType, ok: false, Stopwatch.GetElapsedTime(startedTicks));
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks);

        _logger.LogInformation(
            "Push batch {BatchId} ({BatchName}) to {Destination}: {Sent} sent, {Failed} failed of {Total} meter(s)",
            batch.Id, batch.Name, destination, metersSent, metersFailed, meters.Count);

        return new PushBatchResult(true, meters.Count, metersSent, metersFailed, null);
    }

    /// <summary>
    /// MQTT push: each meter publishes a DataNotification to its NIC's push topic on the broker the
    /// batch is bound to. There is no per-meter source IP here — the node id in the topic is the
    /// identity, and the push arrives on the same broker HES already expects that meter's traffic on.
    /// </summary>
    private async Task<PushBatchResult> PushMqttAsync(MeterBatch batch, CancellationToken cancellationToken, int? maximumMeters, bool selectRandomly)
    {
        NicType transport = NicTypes.TransportFor(batch.NicType);

        // The push must go over the broker this batch is bound to — the same rule as the pull path.
        if (string.IsNullOrWhiteSpace(batch.BrokerKey))
        {
            return PushBatchResult.ForError(
                $"Batch '{batch.Name}' has no broker bound. Bind one on the Network page first.");
        }

        BrokerEndpoint? endpoint = _network.Broker(batch.BrokerKey);
        if (endpoint is null)
        {
            return PushBatchResult.ForError(
                $"Batch '{batch.Name}' is bound to broker '{batch.BrokerKey}', which is not in the registry.");
        }

        if (!endpoint.Enabled)
        {
            return PushBatchResult.ForError($"Broker '{endpoint.Key}' is disabled.");
        }

        var binding = new BrokerBinding(transport, endpoint.Key);
        if (!_mqtt.HasClient(binding))
        {
            // A client only exists for a running batch (§5). No connection, no push.
            return PushBatchResult.ForError(
                $"Broker '{endpoint.Key}' has no live client for {transport}. Start the batch so its " +
                "broker connection comes up, then push.");
        }

        INicCodec? codec = _codecs.Create(transport);
        if (codec is null)
        {
            return PushBatchResult.ForError($"No codec for {transport}; cannot encode a push.");
        }

        // Fail fast on a NIC whose push wire-format is not built yet, rather than per-meter.
        try
        {
            _ = codec.EncodePush("0", new byte[] { 0 });
        }
        catch (NotSupportedException ex)
        {
            return PushBatchResult.ForError(ex.Message);
        }

        IReadOnlyList<(MeterRef Meter, DLMSServerSession Session)> meters = await _sessions.MaterializeBatchAsync(batch, cancellationToken: cancellationToken, maximumMeters: maximumMeters, selectRandomly: selectRandomly);

        int metersSent = 0, metersFailed = 0;
        using var gate = new SemaphoreSlim(Math.Max(1, _options.MaxConcurrency));

        var tasks = meters.Select(async pair =>
        {
            await gate.WaitAsync(cancellationToken);
            long startedTicks = Stopwatch.GetTimestamp();
            try
            {
                byte[][] payloads = await Task.Run(() =>
                {
                    lock (pair.Session)
                    {
                        return pair.Session.BuildPushPayloads(_options.UseCiphering).ToArray();
                    }
                }, cancellationToken);

                if (payloads.Length == 0)
                {
                    _metrics.RecordPushSkipped(batch.NicType);
                    return;
                }

                bool anyFailed = false;
                int published = 0, publishFailed = 0;
                foreach (byte[] payload in payloads)
                {
                    IReadOnlyList<NicPublish> publishes = codec.EncodePush(pair.Meter.NodeId, payload);
                    foreach (NicPublish publish in publishes)
                    {
                        bool ok = await _mqtt.TryPublishPushAsync(binding, publish, _options.PublishQos, cancellationToken);
                        if (ok)
                        {
                            published++;
                        }
                        else
                        {
                            publishFailed++;
                            anyFailed = true;
                        }
                    }
                }

                _metrics.RecordPushPayloads(batch.NicType, published, publishFailed);

                if (anyFailed)
                {
                    Interlocked.Increment(ref metersFailed);
                }
                else
                {
                    Interlocked.Increment(ref metersSent);
                }

                _metrics.RecordPushMeter(batch.NicType, ok: !anyFailed, Stopwatch.GetElapsedTime(startedTicks));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "MQTT push failed for meter {Meter}", pair.Meter);
                Interlocked.Increment(ref metersFailed);
                _metrics.RecordPushMeter(batch.NicType, ok: false, Stopwatch.GetElapsedTime(startedTicks));
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks);

        _logger.LogInformation(
            "MQTT push batch {BatchId} ({BatchName}) via {Binding}: {Sent} sent, {Failed} failed of {Total} meter(s)",
            batch.Id, batch.Name, binding, metersSent, metersFailed, meters.Count);

        return new PushBatchResult(true, meters.Count, metersSent, metersFailed, null);
    }

    /// <summary>
    /// Where this batch's push goes: the typed override if there is one, otherwise its bound
    /// registry target.
    ///
    /// <para>
    /// A disabled target is refused rather than silently used. Disabling is the operator saying
    /// "stop talking to this", and honouring it only for MQTT while push ignored it would make the
    /// toggle mean two different things on one page.
    /// </para>
    /// </summary>
    private bool TryResolveDestination(MeterBatch batch, string? typed, out string destination, out string error)
    {
        error = string.Empty;

        if (!string.IsNullOrWhiteSpace(typed))
        {
            destination = typed.Trim();
            return true;
        }

        destination = string.Empty;

        if (string.IsNullOrWhiteSpace(batch.PushTargetKey))
        {
            error = $"Batch '{batch.Name}' has no push target bound. Bind one on the Network page, " +
                    "or type a destination.";
            return false;
        }

        PushTargetEndpoint? target = _network.PushTarget(batch.PushTargetKey);
        if (target is null)
        {
            error = $"Batch '{batch.Name}' is bound to push target '{batch.PushTargetKey}', which is " +
                    "not in the network registry.";
            return false;
        }

        if (!target.Enabled)
        {
            error = $"Push target '{target.Key}' is disabled.";
            return false;
        }

        destination = target.Destination;
        return true;
    }
}

/// <summary>
/// Seam for the scheduled push that replaces the dashboard button (network_registry.md §6).
///
/// <para>
/// Deliberately empty of scheduling logic: it exists now so the eventual timer has an obvious home
/// and does not reopen <see cref="PushCoordinator"/>, whose job is one batch, once, on demand.
/// A batch's <see cref="MeterBatch.PushTargetKey"/> is what an implementation will read — the typed
/// override has no meaning without an operator at the keyboard.
/// </para>
/// </summary>
public interface IPushScheduler
{
    /// <summary>Batches that a scheduled push would currently cover: 4G TCP, Running, and bound.</summary>
    IReadOnlyList<MeterBatch> ScheduledBatches();
}

/// <summary>Outcome of a "Send Push" click over a whole batch.</summary>
public readonly record struct PushBatchResult(bool Ok, int Total, int Sent, int Failed, string? Error)
{
    public static PushBatchResult ForError(string error) => new(false, 0, 0, 0, error);
}
