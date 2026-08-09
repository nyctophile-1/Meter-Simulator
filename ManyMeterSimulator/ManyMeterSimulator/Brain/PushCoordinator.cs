using ManyMeterSimulator.Networking.Nic;
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
    private readonly PushOptions _options;
    private readonly ILogger<PushCoordinator> _logger;

    public PushCoordinator(
        MeterRegistry registry,
        MeterSessionManager sessions,
        NetworkRegistry network,
        IOptions<PushOptions> options,
        ILogger<PushCoordinator> logger)
    {
        _registry = registry;
        _sessions = sessions;
        _network = network;
        _options = options.Value;
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
        int batchId, string? destination = null, CancellationToken cancellationToken = default)
    {
        MeterBatch? batch = _registry.Batches.FirstOrDefault(b => b.Id == batchId);
        if (batch is null)
        {
            return PushBatchResult.ForError($"Batch {batchId} no longer exists.");
        }

        if (batch.NicType != NicType.Tcp4G)
        {
            // Only TCP meters have a per-meter IP to originate a push from; MQTT meters would have no
            // source identity for the receiver to correlate on.
            return PushBatchResult.ForError($"Push is only supported for 4G TCP batches (batch is {batch.NicType}).");
        }

        if (!TryResolveDestination(batch, destination, out string resolved, out string error))
        {
            return PushBatchResult.ForError(error);
        }

        destination = resolved;

        IReadOnlyList<(MeterRef Meter, DLMSServerSession Session)> meters = _sessions.MaterializeBatch(batch);

        int metersSent = 0, metersFailed = 0;
        using var gate = new SemaphoreSlim(Math.Max(1, _options.MaxConcurrency));

        var tasks = meters.Select(async pair =>
        {
            await gate.WaitAsync(cancellationToken);
            try
            {
                // PushNow does blocking socket IO and mutates the session's push objects; offload it
                // and serialize per session (same lock the inbound bridge takes).
                PushSendResult result = await Task.Run(() =>
                {
                    lock (pair.Session)
                    {
                        return pair.Session.PushNow(destination, _options.DefaultPort, _options.UseCiphering);
                    }
                }, cancellationToken);

                if (result.Failed == 0 && result.Sent > 0)
                {
                    Interlocked.Increment(ref metersSent);
                }
                else if (result.Sent > 0)
                {
                    // Some PushSetups sent, some failed — count the meter as partially failed.
                    Interlocked.Increment(ref metersFailed);
                }
                else if (result.Failed > 0)
                {
                    Interlocked.Increment(ref metersFailed);
                }
                // result.Sent == 0 && result.Failed == 0 → meter has no PushSetup; not counted either way.
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Push failed for meter {Meter}", pair.Meter);
                Interlocked.Increment(ref metersFailed);
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
