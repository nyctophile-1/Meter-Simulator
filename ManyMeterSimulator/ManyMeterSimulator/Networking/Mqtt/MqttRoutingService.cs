using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Networking.Mqtt;

public sealed class MqttRoutingService(
    MeterRegistry registry,
    NetworkRegistry network,
    IMqttRoutingPublisher publisher,
    ILogger<MqttRoutingService> logger) : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
                await PublishRoutingAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    public async Task PublishRoutingAsync(CancellationToken cancellationToken)
    {
        foreach (var batch in registry.Batches)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (batch.Status != BatchStatus.Running) continue;

            var endpoint = batch.BrokerKey is { } key ? network.Broker(key) : null;
            if (endpoint is not { Enabled: true }) continue;

            long sent = 0;
            try
            {
                await using var pool = await publisher.OpenPoolAsync(endpoint, cancellationToken);
                for (long index = batch.StartIndex; index <= batch.EndIndex; index++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!IsCurrent()) break;
                    var message = new NicPublish(
                        NicTopics.FakeRouting(MeterNodeIds.Format(index), batch.NicType), Array.Empty<byte>());
                    var delivery = await pool.PublishMeterAsync([message], cancellationToken);
                    sent += delivery.Sent;
                    if (delivery.Failed > 0)
                        throw new IOException(delivery.Error ?? "Routing publish failed.");
                }
                logger.LogInformation("Routing batch {BatchId}: sent {Sent}/{Count} empty MQTT messages",
                    batch.Id, sent, batch.Count);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Routing batch {BatchId}: stopped after {Sent}/{Count} messages; next attempt in the next routing cycle",
                    batch.Id, sent, batch.Count);
            }

            bool IsCurrent() => batch.Status == BatchStatus.Running &&
                string.Equals(batch.BrokerKey, endpoint.Key, StringComparison.OrdinalIgnoreCase) &&
                registry.Batches.Contains(batch) && network.Broker(endpoint.Key) is { Enabled: true } current &&
                current.Host == endpoint.Host && current.Port == endpoint.Port &&
                current.UseTls == endpoint.UseTls && current.Username == endpoint.Username &&
                current.Password == endpoint.Password;
        }
    }
}
