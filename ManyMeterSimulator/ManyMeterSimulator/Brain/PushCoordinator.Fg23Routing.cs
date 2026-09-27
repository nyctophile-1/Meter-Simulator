using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Brain;

public sealed partial class PushCoordinator
{
    private MqttPushSource ResolveFg23RoutingSource(int batchId, MqttPushRequest request)
    {
        var batch = _registry.Batches.FirstOrDefault(b => b.Id == batchId)
            ?? throw new InvalidOperationException($"Batch {batchId} no longer exists.");

        if (batch.NicType != NicType.MqttWirepas)
        {
            throw new InvalidOperationException($"Batch '{batch.Name}': FG23 Routing requires Wirepas meters.");
        }

        var endpoint = batch.BrokerKey is { } key ? _network.Broker(key) : null;

        if (endpoint is not { Enabled: true })
        {
            throw new InvalidOperationException($"Batch '{batch.Name}': FG23 Routing requires an enabled broker.");
        }

        var binding = new BrokerBinding(NicTypes.TransportFor(batch.NicType), endpoint.Key);

        if (!_mqtt.HasClient(binding))
        {
            throw new InvalidOperationException($"Broker '{endpoint.Key}' has no live Wirepas client. Start the batch first.");
        }

        long count = Math.Min(batch.Count, request.MaximumMetersPerBatch ?? int.MaxValue);
        long startIndex = batch.StartIndex;
        long batchCount = batch.Count;
        var status = batch.Status;
        string? environment = batch.EnvironmentKey;

        return new MqttPushSource(batch.Id, count, binding, Meters, Build, IsCurrent);

        IEnumerable<MeterRef> Meters()
        {
            if (request.SelectRandomly && count < batchCount)
            {
                var selected = new HashSet<long>();

                for (long j = batchCount - count; j < batchCount; j++)
                {
                    long candidate = Random.Shared.NextInt64(j + 1);
                    long ordinal = selected.Add(candidate) ? candidate : j;
                    selected.Add(ordinal);

                    yield return new MeterRef(startIndex + ordinal, NicType.MqttWirepas);
                }
            }
            else
            {
                for (long i = 0; i < count; i++)
                {
                    yield return new MeterRef(startIndex + i, NicType.MqttWirepas);
                }
            }
        }

        IReadOnlyList<NicPublish> Build(MeterRef meter)
        {
            var route = BatchGatewayAssignment.For(batch.Id, startIndex, meter.Index);

            // Routing consumes the envelope metadata; no firmware diagnostic body is needed.
            return [WirepasCustomPushEnvelope.Create(route.Gateway, route.Sink, meter.NodeId, 247, [])];
        }

        bool IsCurrent()
        {
            var current = _registry.Batches.FirstOrDefault(b => b.Id == batchId);
            var broker = _network.Broker(endpoint.Key);

            return ReferenceEquals(current, batch)
                && current!.NicType == NicType.MqttWirepas
                && current.EnvironmentKey == environment
                && current.BrokerKey == endpoint.Key
                && current.Status == status
                && current.StartIndex == startIndex
                && current.Count == batchCount
                && broker is { Enabled: true }
                && broker.Host == endpoint.Host
                && broker.Port == endpoint.Port
                && broker.UseTls == endpoint.UseTls
                && broker.Username == endpoint.Username
                && broker.Password == endpoint.Password;
        }
    }
}
