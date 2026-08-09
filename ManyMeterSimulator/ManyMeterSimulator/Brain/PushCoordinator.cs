using ManyMeterSimulator.Networking.Nic;
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
    private readonly PushOptions _options;
    private readonly ILogger<PushCoordinator> _logger;

    public PushCoordinator(
        MeterRegistry registry,
        MeterSessionManager sessions,
        IOptions<PushOptions> options,
        ILogger<PushCoordinator> logger)
    {
        _registry = registry;
        _sessions = sessions;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>The port applied to a bare-IP destination, and the ciphering/default the UI shows.</summary>
    public PushOptions Options => _options;

    /// <summary>
    /// Pushes every meter in a batch to <paramref name="destination"/> ("ip", "ip:port", or
    /// "[ipv6]:port"). Meters are materialized first so a never-polled batch can still push. Sends run
    /// concurrently up to <see cref="PushOptions.MaxConcurrency"/>; each meter's push is serialized
    /// against its own session lock so it can't collide with an in-flight HES pull.
    /// </summary>
    public async Task<PushBatchResult> PushBatchAsync(int batchId, string destination, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(destination))
        {
            return PushBatchResult.ForError("Enter a push destination IP first.");
        }

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
}

/// <summary>Outcome of a "Send Push" click over a whole batch.</summary>
public readonly record struct PushBatchResult(bool Ok, int Total, int Sent, int Failed, string? Error)
{
    public static PushBatchResult ForError(string error) => new(false, 0, 0, 0, error);
}
