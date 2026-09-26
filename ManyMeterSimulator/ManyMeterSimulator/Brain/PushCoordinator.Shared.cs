using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using ManyMeterSimulator.Settings;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using System.Collections.Concurrent;

namespace ManyMeterSimulator.Brain;

public sealed partial class PushCoordinator
{
    private readonly ConcurrentDictionary<int, string> _eventStatusWordOverrides = new();
    private readonly BadCommSettings? _badComm;
    private readonly NetworkDelaySettings? _networkDelay;

    internal int BlockCapturePeriodSeconds(MeterBatch batch)
    {
        if (batch.NicType == NicType.MqttWirepas)
            return checked(_customPullOptions.GetBlockPeriodMinutes(batch.HesTemplateId
                ?? throw new InvalidOperationException("Wirepas Block Load needs a HES template mapping.")) * 60);
        return _sessions.GetOrCreate(new MeterRef(batch.StartIndex, batch.NicType)).BlockPushPeriodSeconds;
    }

    private byte[][] BuildDlms(MeterRef meter, bool ciphering, string? profile, DateTimeOffset? timestamp = null,
        ushort powerEventId = 101, DateTimeOffset? scheduledBlockSlot = null)
    {
        var session = _sessions.GetOrCreate(meter);
        lock (session)
        {
            ApplyEventStatusWord(meter, session);
            return session.BuildPushPayloads(ciphering, profile, timestamp, powerEventId, scheduledBlockSlot).ToArray();
        }
    }

    public void SetEventStatusWord(int batchId, string value)
    {
        EventStatusWord.Validate(value);
        _eventStatusWordOverrides[batchId] = value;
    }

    private void ApplyEventStatusWord(MeterRef meter, DLMSServerSession session)
    {
        var batch = _registry.GetBatchForIndex(meter.Index);
        if (batch is not null && _eventStatusWordOverrides.TryGetValue(batch.Id, out string? value))
            session.SetEventStatusWord(value);
    }

    private Task<bool> AllowPushAsync(MeterRef meter, CancellationToken token) => AllowPushAsync(meter, token, true);

    private async Task<bool> AllowPushAsync(MeterRef meter, CancellationToken token, bool simulateNetworkDelay)
    {
        token.ThrowIfCancellationRequested();
        var impairment = (_badComm?.GetClassifier(CommunicationDirection.Push) ?? MeterClassifier.Disabled).Classify(meter.Index);
        if (impairment.Class == CommClass.NonComm)
        {
            _metrics.RecordNonCommDrop();
            return false;
        }
        int delay = simulateNetworkDelay
            ? NetworkDelaySettings.ApplyImpairment(_networkDelay?.NextDelayMs(CommunicationDirection.Push) ?? 0, impairment.Multiplier)
            : 0;
        if (delay > 0) await Task.Delay(delay, token);
        _metrics.RecordNetworkDelay(TimeSpan.FromMilliseconds(delay));
        if (impairment.Class == CommClass.BadComm)
        {
            _metrics.RecordBadCommDelay(TimeSpan.FromMilliseconds(delay));
            if (Random.Shared.NextDouble() * 100 < impairment.FailureRatePercent)
            {
                _metrics.RecordBadCommDrop();
                return false;
            }
        }
        return true;
    }
}

internal sealed class PushSkippedException : Exception;
