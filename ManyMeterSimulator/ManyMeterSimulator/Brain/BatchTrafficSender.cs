using System.Diagnostics;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Brain;

public sealed class BatchTrafficSender(PushCoordinator push, NetworkRegistry network,
    IMqttRoutingPublisher routing) : IBatchTrafficSender
{
    public async Task<IBatchTrafficSession> OpenAsync(MeterBatch batch, BatchTrafficKind kind, CancellationToken token)
    {
        if (kind != BatchTrafficKind.Routing)
        {
            return await push.OpenBatchTrafficAsync(batch, kind, token);
        }

        var endpoint = batch.BrokerKey is { } key ? network.Broker(key) : null;

        if (endpoint is not { Enabled: true })
        {
            throw new InvalidOperationException("Routing needs an enabled broker in the batch's environment.");
        }

        var pool = await routing.OpenPoolAsync(endpoint, token);

        return new BatchTrafficSession(async (index, ct) =>
        {
            ct.ThrowIfCancellationRequested();

            var current = batch.BrokerKey is { } binding ? network.Broker(binding) : null;

            if (current is not { Enabled: true } || current.Key != endpoint.Key || current.Host != endpoint.Host
                || current.Port != endpoint.Port || current.UseTls != endpoint.UseTls
                || current.Username != endpoint.Username || current.Password != endpoint.Password)
            {
                throw new InvalidOperationException("Routing broker changed; reconnecting.");
            }

            var result = await pool.PublishMeterAsync([new(NicTopics.FakeRouting(batch, index), [])], ct);

            if (result.Failed > 0)
            {
                throw new IOException(result.Error ?? "Routing publish failed.");
            }
        }, pool.DisposeAsync);
    }
}

internal sealed class BatchTrafficSession(Func<long, CancellationToken, Task> send, Func<ValueTask> dispose) : IBatchTrafficSession
{
    public Task SendAsync(long meterIndex, CancellationToken token) => send(meterIndex, token);
    public ValueTask DisposeAsync() => dispose();
}

public sealed partial class PushCoordinator
{
    internal async Task<IBatchTrafficSession> OpenBatchTrafficAsync(MeterBatch batch, BatchTrafficKind kind, CancellationToken token)
    {
        string profile = kind switch
        {
            BatchTrafficKind.Instantaneous => "0.0.25.9.0.255",
            BatchTrafficKind.BlockLoad => "0.5.25.9.0.255",
            BatchTrafficKind.Daily => "0.6.25.9.0.255",
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        if (batch.NicType == NicType.Tcp4G)
        {
            var source = ResolveTcpSource(batch.Id, new TcpPushRequest { BatchIds = [batch.Id], PushSetupLogicalName = profile }, _options.UseCiphering);
            return new BatchTrafficSession(async (index, ct) =>
            {
                ct.ThrowIfCancellationRequested();
                if (!source.IsCurrent()) throw new InvalidOperationException("TCP batch or target changed; reconnecting.");
                long started = Stopwatch.GetTimestamp();
                var meter = new MeterRef(index, batch.NicType);
                if (!await AllowPushAsync(meter, ct))
                { _metrics.RecordPushSkipped(batch.NicType); throw new PushSkippedException(); }
                PushDeliveryResult result;
                try { result = await source.Send(meter, source.Build(meter), ct); }
                catch (PushCanceledException ex)
                {
                    RecordCanceledTraffic(batch.NicType, ex, started);
                    throw;
                }
                _metrics.RecordPushPayloads(batch.NicType, result.Sent, result.Failed);
                _metrics.RecordPushMeter(batch.NicType, result.Sent > 0 && result.Failed == 0, Stopwatch.GetElapsedTime(started));
                if (result.Failed > 0 || result.Sent == 0) throw new IOException(result.Error ?? "TCP push produced no payloads.");
            }, () => ValueTask.CompletedTask);
        }
        var mqtt = ResolveMqttSource(batch.Id, new MqttPushRequest { BatchIds = [batch.Id], PushSetupLogicalName = profile });
        var pool = await _mqtt.OpenPoolAsync(mqtt.Binding, _options.PublisherCount, _options.PublishQos, _options.PublishTimeoutSeconds, token);
        return new BatchTrafficSession(async (index, ct) =>
        {
            ct.ThrowIfCancellationRequested();
            if (!mqtt.IsCurrent()) throw new InvalidOperationException("MQTT batch or broker changed; reconnecting.");
            long started = Stopwatch.GetTimestamp();
            if (!await AllowPushAsync(new MeterRef(index, batch.NicType), ct))
            { _metrics.RecordPushSkipped(batch.NicType); throw new PushSkippedException(); }
            MqttPushDelivery result;
            try { result = await pool.PublishMeterAsync(mqtt.Build(new MeterRef(index, batch.NicType)), ct); }
            catch (PushCanceledException ex)
            {
                RecordCanceledTraffic(batch.NicType, ex, started);
                throw;
            }
            _metrics.RecordPushPayloads(batch.NicType, result.Sent, result.Failed);
            _metrics.RecordPushMeter(batch.NicType, result.Sent > 0 && result.Failed == 0, Stopwatch.GetElapsedTime(started));
            if (result.Failed > 0 || result.Sent == 0) throw new IOException(result.Error ?? "MQTT push failed or produced no payloads.");
        }, pool.DisposeAsync);
    }

    private void RecordCanceledTraffic(NicType nic, PushCanceledException error, long started)
    {
        _metrics.RecordPushPayloads(nic, error.Sent, error.Failed);
        _metrics.RecordPushMeter(nic, false, Stopwatch.GetElapsedTime(started));
    }
}
