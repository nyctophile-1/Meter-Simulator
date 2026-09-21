using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Brain;

public sealed partial class PushCoordinator
{
    public async Task<TcpPushRun> OpenTcpRunAsync(TcpPushRequest request, CancellationToken cancellationToken = default)
    {
        request = request with { BatchIds = request.BatchIds.ToArray() };
        request.Validate();
        cancellationToken.ThrowIfCancellationRequested();
        bool ciphering = _options.UseCiphering;
        var connections = new TcpPushConnectionGroup();
        IDisposable? lease = null;
        try
        {
            var sources = request.BatchIds.Select(id => ResolveTcpSource(id, request, ciphering, connections)).ToArray();
            lease = _registry.AcquirePushLease(request.BatchIds);
            return new TcpPushRun(sources, request, ciphering, cancellationToken,
                handler =>
                {
                    _registry.Changed += handler;
                    _network.Changed += handler;
                },
                handler =>
                {
                    _registry.Changed -= handler;
                    _network.Changed -= handler;
                }, _metrics, lease, connections);
        }
        catch
        {
            lease?.Dispose();
            await connections.DisposeAsync();
            throw;
        }
    }

    private TcpPushSource ResolveTcpSource(int batchId, TcpPushRequest request, bool ciphering, TcpPushConnectionGroup? connections = null)
    {
        var batch = _registry.Batches.FirstOrDefault(b => b.Id == batchId)
            ?? throw new InvalidOperationException($"Batch {batchId} no longer exists.");
        if (batch.NicType != NicType.Tcp4G || batch.Status != BatchStatus.Running)
        {
            throw new InvalidOperationException($"Batch '{batch.Name}' must be a running TCP batch.");
        }

        if (!TryResolveDestination(batch, null, out string destination, out string error))
        {
            throw new InvalidOperationException(error);
        }

        if (!TcpPushSender.TryParseDestination(destination, _options.DefaultPort, out _, out int port) || port is < 1 or > 65535)
        {
            throw new InvalidOperationException($"Batch '{batch.Name}' has an invalid TCP destination.");
        }

        var first = _sessions.GetOrCreate(new MeterRef(batch.StartIndex, NicType.Tcp4G));
        string? selection = MqttPushProfiles.ForNic(request.PushSetupLogicalName, batch.NicType);
        lock (first)
        {
            var profiles = first.GetPushSetupLogicalNames();
            if (profiles.Count == 0 || selection is { } profile && !profiles.Contains(profile))
            {
                throw new InvalidOperationException($"Batch '{batch.Name}' cannot build {MqttPushProfiles.Label(selection)} from template '{batch.TemplateName}': the push setup or required profile data is missing.");
            }
        }

        string? environment = batch.EnvironmentKey;
        var powerSequence = new PowerEventSequence();
        var deliveries = new System.Runtime.CompilerServices.ConditionalWeakTable<byte[][], DlmsPowerDelivery>();
        long count = Math.Min(batch.Count, request.MaximumMetersPerBatch ?? int.MaxValue);
        return new(count, Meters, Build, Send, IsCurrent, BuildAt);

        IEnumerable<MeterRef> Meters()
        {
            if (request.SelectRandomly && count < batch.Count)
            {
                var selected = new HashSet<long>();
                for (long j = batch.Count - count; j < batch.Count; j++)
                {
                    long candidate = Random.Shared.NextInt64(j + 1);
                    long ordinal = selected.Add(candidate) ? candidate : j;
                    selected.Add(ordinal);
                    yield return new MeterRef(batch.StartIndex + ordinal, NicType.Tcp4G);
                }
            }
            else
            {
                for (long i = 0; i < count; i++)
                {
                    yield return new MeterRef(batch.StartIndex + i, NicType.Tcp4G);
                }
            }
        }

        byte[][] Build(MeterRef meter)
            => BuildAt(meter, null);

        byte[][] BuildAt(MeterRef meter, DateTimeOffset? timestamp)
        {
            var delivery = BuildTrackedDlms(meter, ciphering, selection, powerSequence, timestamp);
            if (delivery.Confirm is not null)
            {
                deliveries.Add(delivery.Payloads, delivery);
            }

            return delivery.Payloads;
        }

        Task<PushDeliveryResult> Send(MeterRef meter, byte[][] payloads, CancellationToken token) =>
            _tcpPush.SendAsync(meter.Serial, _sessions.GetOrCreate(meter).SourceAddress,
                destination, _options.DefaultPort, payloads, token,
                deliveries.TryGetValue(payloads, out var delivery) ? delivery.Confirm : null, request.WaitForPeerCloseSeconds, connections);

        bool IsCurrent() => ReferenceEquals(_registry.GetBatchForIndex(batch.StartIndex), batch)
            && batch.Status == BatchStatus.Running && batch.EnvironmentKey == environment
            && TryResolveDestination(batch, null, out string current, out _) && current == destination;
    }
}
