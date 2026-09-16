using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using ManyMeterSimulator.Networking.SmartNic;

namespace ManyMeterSimulator.Brain;

public sealed partial class PushCoordinator
{
    private async Task<PushBatchResult> PushMqttAsync(MeterBatch batch, CancellationToken cancellationToken,
        int? maximumMeters, bool selectRandomly, string? pushSetupLogicalName = null)
    {
        try
        {
            await using var run = await OpenMqttRunAsync(new MqttPushRequest
            {
                BatchIds = [batch.Id], PublisherCount = _options.PublisherCount, Qos = _options.PublishQos,
                MaxConcurrency = Math.Max(_options.MaxConcurrency, _options.PublisherCount),
                MaximumMetersPerBatch = maximumMeters, SelectRandomly = selectRandomly,
                PushSetupLogicalName = pushSetupLogicalName,
                ChunkSize = _options.ChunkSize == int.MaxValue ? 0 : Math.Clamp(_options.ChunkSize, 0, 1_000_000),
                ChunkIntervalSeconds = _options.ChunkIntervalSeconds,
            }, cancellationToken);
            var result = await run.SendLiveAsync();
            _logger.LogInformation("MQTT push batch {BatchId}: {Sent} meters sent, {Failed} failed, {Skipped} skipped; " +
                "{Messages} publishes completed, {Rejected} failed/unconfirmed. {Error}", batch.Id,
                result.MetersSent, result.MetersFailed, result.MetersSkipped, result.MessagesSent, result.MessagesFailed, result.Error);
            return new PushBatchResult(true, (int)run.TotalMeters, (int)result.MetersSent, (int)result.MetersFailed, result.Error);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { return PushBatchResult.ForError(ex.Message); }
    }

    /// <summary>Opens one publish-only pool per selected broker/transport. This sends no payloads.</summary>
    public async Task<MqttPushRun> OpenMqttRunAsync(MqttPushRequest request, CancellationToken cancellationToken = default)
    {
        request = request with { BatchIds = request.BatchIds.ToArray() };
        request.Validate();
        var sources = request.BatchIds.Select(id => ResolveMqttSource(id, request)).ToArray();
        var pools = new Dictionary<BrokerBinding, IMqttPushPool>();
        var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            foreach (BrokerBinding binding in sources.Select(s => s.Binding).Distinct())
                pools.Add(binding, await _mqtt.OpenPoolAsync(binding, request.PublisherCount, request.Qos,
                    _options.PublishTimeoutSeconds, stop.Token));
            return new MqttPushRun(sources, pools, request, _options.UseCiphering, stop,
                handler => { _registry.Changed += handler; _network.Changed += handler; },
                handler => { _registry.Changed -= handler; _network.Changed -= handler; }, _metrics);
        }
        catch
        {
            stop.Cancel();
            await Task.WhenAll(pools.Values.Select(async p => await p.DisposeAsync()));
            stop.Dispose();
            throw;
        }
    }

    private MqttPushSource ResolveMqttSource(int batchId, MqttPushRequest request)
    {
        MeterBatch batch = _registry.Batches.FirstOrDefault(b => b.Id == batchId)
            ?? throw new InvalidOperationException($"Batch {batchId} no longer exists.");
        if (!NicTypes.IsMqtt(batch.NicType)) throw new InvalidOperationException($"Batch '{batch.Name}' is not an MQTT batch.");
        if (string.IsNullOrWhiteSpace(batch.BrokerKey))
            throw new InvalidOperationException($"Batch '{batch.Name}' has no broker bound. Bind one on the Network page first.");
        BrokerEndpoint endpoint = _network.Broker(batch.BrokerKey)
            ?? throw new InvalidOperationException($"Broker '{batch.BrokerKey}' is not in the registry.");
        if (!endpoint.Enabled) throw new InvalidOperationException($"Broker '{endpoint.Key}' is disabled.");
        var binding = new BrokerBinding(NicTypes.TransportFor(batch.NicType), endpoint.Key);
        if (!_mqtt.HasClient(binding))
            throw new InvalidOperationException($"Broker '{endpoint.Key}' has no live client for {binding.Transport}. Start the batch first.");

        string? selection = request.PushSetupLogicalName == "custom:93:daily" ? MqttPushProfiles.CustomDaily : request.PushSetupLogicalName;
        if (selection is null && batch.NicType == NicType.MqttWirepas && batch.HesTemplateId is int declaredTemplate
            && !_customEncoder.HasTemplate(declaredTemplate))
            throw new InvalidOperationException($"HES template {declaredTemplate} is missing; select DLMS explicitly or configure its push metadata.");
        bool custom = selection?.StartsWith("custom:", StringComparison.Ordinal) == true ||
            selection is null && batch.NicType == NicType.MqttWirepas && _customEncoder.IsCustomTemplate(batch.HesTemplateId);
        IReadOnlyList<CustomPushProfile> customProfiles = [];
        INicCodec? codec = null;
        if (custom)
        {
            if (batch.NicType != NicType.MqttWirepas || batch.CustomPushHeaderKind != CustomPushHeaderKind.New)
                throw new InvalidOperationException("Custom push requires Wirepas with the configured new header.");
            customProfiles = _customEncoder.GetProfiles(batch.HesTemplateId ?? throw new InvalidOperationException("Custom push requires a HES template mapping."));
            if (selection is not null)
                customProfiles = [customProfiles.SingleOrDefault(p => p.Key == selection)
                    ?? throw new InvalidOperationException($"Batch '{batch.Name}' does not support {selection}.")];
            if (customProfiles.Any(p => p.Kind == "ESW"))
            {
                var first = _sessions.GetOrCreate(new MeterRef(batch.StartIndex, batch.NicType));
                lock (first) _ = first.GetEventStatusWord();
            }
        }
        else
        {
            codec = _codecs.CreatePush(binding.Transport, _customPushOptions.WirepasGatewayId,
                _customPushOptions.WirepasSinkId, _options.KmeshGatewayId, _options.KmeshSinkId)
                ?? throw new InvalidOperationException($"No push codec for {binding.Transport}.");
            _ = codec.EncodePush(new MeterRef(batch.StartIndex, batch.NicType).NodeId, new byte[] { 0 });
            var session = _sessions.GetOrCreate(new MeterRef(batch.StartIndex, batch.NicType));
            IReadOnlyList<string> profiles;
            lock (session) profiles = session.GetPushSetupLogicalNames();
            if (profiles.Count == 0 || request.PushSetupLogicalName is { } selected && !profiles.Contains(selected))
                throw new InvalidOperationException($"Batch '{batch.Name}' has no non-empty push setup for {MqttPushProfiles.Label(request.PushSetupLogicalName)}.");
        }

        long count = Math.Min(batch.Count, request.MaximumMetersPerBatch ?? int.MaxValue);
        string? environment = batch.EnvironmentKey;
        BatchStatus status = batch.Status;
        string template = batch.TemplateName;
        long startIndex = batch.StartIndex;
        int? hesTemplate = batch.HesTemplateId;
        var header = batch.CustomPushHeaderKind;
        return new MqttPushSource(batch.Id, count, binding, Meters, Build, IsCurrent);

        IEnumerable<MeterRef> Meters()
        {
            if (request.SelectRandomly && count < batch.Count)
            {
                // Floyd's sampling algorithm: O(sample size), with no duplicate/retry tail.
                var selected = new HashSet<long>();
                for (long j = batch.Count - count; j < batch.Count; j++)
                {
                    long candidate = Random.Shared.NextInt64(j + 1);
                    long ordinal = selected.Add(candidate) ? candidate : j;
                    selected.Add(ordinal);
                    yield return new MeterRef(startIndex + ordinal, batch.NicType);
                }
            }
            else
                for (long i = 0; i < count; i++) yield return new MeterRef(startIndex + i, batch.NicType);
        }

        IReadOnlyList<NicPublish> Build(MeterRef meter)
        {
            if (custom)
            {
                var packets = new List<byte[]>(customProfiles.Count);
                string? esw = null;
                if (customProfiles.Any(p => p.Kind == "ESW"))
                {
                    var eswSession = _sessions.GetOrCreate(meter);
                    lock (eswSession) esw = eswSession.GetEventStatusWord();
                }
                var timestamp = DateTimeOffset.UtcNow;
                foreach (var profile in customProfiles)
                    packets.Add(_customEncoder.Encode(batch.HesTemplateId!.Value, profile.Key, meter.Index,
                        unchecked((uint)Random.Shared.NextInt64()), timestamp,
                        field => CustomProfileDataGenerator.Value(field, meter.Index, timestamp, profile.Kind, profile.EventId), esw));
                return packets.Select(packet => WirepasCustomPushEnvelope.Create(_customPushOptions.WirepasGatewayId,
                    _customPushOptions.WirepasSinkId, meter.NodeId, _customPushOptions.WirepasEndpoint,
                    packet)).ToArray();
            }

            var session = _sessions.GetOrCreate(meter);
            byte[][] payloads;
            lock (session) payloads = session.BuildPushPayloads(_options.UseCiphering, request.PushSetupLogicalName).ToArray();
            // Codec instances can carry frame state. Only encoding is serialized, never network I/O.
            lock (codec!) return payloads.SelectMany(p => codec.EncodePush(meter.NodeId, p)).ToArray();
        }

        bool IsCurrent()
        {
            var current = _registry.Batches.FirstOrDefault(b => b.Id == batchId);
            var broker = _network.Broker(endpoint.Key);
            return current is not null && current.EnvironmentKey == environment && current.Status == status
                && current.TemplateName == template && current.StartIndex == startIndex && current.Count == batch.Count
                && current.HesTemplateId == hesTemplate && current.CustomPushHeaderKind == header
                && broker is { Enabled: true } && broker.Host == endpoint.Host && broker.Port == endpoint.Port
                && broker.UseTls == endpoint.UseTls && broker.Username == endpoint.Username && broker.Password == endpoint.Password;
        }
    }
}
