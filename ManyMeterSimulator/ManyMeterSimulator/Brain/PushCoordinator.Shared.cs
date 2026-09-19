using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Settings;
using MeterSimulator.DLMS;

namespace ManyMeterSimulator.Brain;

public sealed partial class PushCoordinator
{
    private readonly BadCommSettings? _badComm;
    private readonly NetworkDelaySettings? _networkDelay;

    private byte[][] BuildDlms(MeterRef meter, bool ciphering, string? profile, DateTimeOffset? timestamp = null, ushort powerEventId = 101)
    {
        var session = _sessions.GetOrCreate(meter);
        lock (session) return session.BuildPushPayloads(ciphering, profile, timestamp, powerEventId).ToArray();
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
