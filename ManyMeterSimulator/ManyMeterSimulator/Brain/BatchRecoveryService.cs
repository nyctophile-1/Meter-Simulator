using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Brain;

/// <summary>Owns restart recovery and observes its work for the lifetime of the host.</summary>
public sealed class BatchRecoveryService(
    MeterRegistry registry, MeterSessionManager sessions, ILogger<BatchRecoveryService> logger) : BackgroundService
{
    public override Task StartAsync(CancellationToken cancellationToken)
    {
        // Close admission before any listeners start: persisted Running is only intent until loaded.
        foreach (var batch in registry.Batches.Where(b => b.Status == BatchStatus.Running))
            registry.TryMarkStarting(batch.Id);
        return base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        foreach (var batch in registry.Batches.Where(b => b.Status == BatchStatus.Starting))
        {
            if (stoppingToken.IsCancellationRequested) break;
            if (batch.Status != BatchStatus.Starting) continue;
            try
            {
                // One batch at a time; each loader already uses all available CPU workers.
                await sessions.StartBatchAsync(batch, stoppingToken);
                logger.LogInformation("Recovered batch {BatchId} ({Count} meters)", batch.Id, batch.Count);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                logger.LogError(ex, "Could not recover batch {BatchId} ({Name})", batch.Id, batch.Name);
            }
        }
    }
}
