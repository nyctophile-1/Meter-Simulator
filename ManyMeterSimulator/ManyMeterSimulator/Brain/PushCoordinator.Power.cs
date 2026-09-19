using System.Runtime.CompilerServices;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Brain;

public sealed partial class PushCoordinator
{
    private readonly ConditionalWeakTable<MeterBatch, PowerEventSequence> _normalPower = new();

    private void RemoveRetiredPowerSequences()
    {
        var current = _registry.Batches.ToHashSet(ReferenceEqualityComparer.Instance);
        foreach (var entry in _normalPower)
            if (!current.Contains(entry.Key)) _normalPower.Remove(entry.Key);
    }

    private sealed record DlmsPowerDelivery(byte[][] Payloads, Action<int>? Confirm);

    private DlmsPowerDelivery BuildTrackedDlms(MeterRef meter, bool ciphering, string? selection,
        PowerEventSequence sequence, DateTimeOffset? timestamp = null)
    {
        if (selection is not (null or MqttPushProfiles.Power))
            return new(BuildDlms(meter, ciphering, selection, timestamp), null);
        var session = _sessions.GetOrCreate(meter);
        bool power;
        lock (session) power = (selection is null or MqttPushProfiles.Power) && session.GetPushSetupLogicalNames().Contains(MqttPushProfiles.Power);
        ushort eventId = power ? sequence.Next(meter.Index) : (ushort)101;
        var payloads = BuildDlms(meter, ciphering, selection, timestamp, eventId);
        // The core appends the power event after the other selected profiles.
        Action<int>? confirm = power ? index =>
        {
            if (index == payloads.Length - 1) sequence.Confirm(meter.Index, eventId);
        } : null;
        return new(payloads, confirm);
    }

    private static IReadOnlyList<NicPublish> TrackPowerFragments(IReadOnlyList<NicPublish> messages, Action confirm)
    {
        int remaining = messages.Count;
        return messages.Select(message =>
        {
            int confirmed = 0;
            return message with { DeliveryConfirmed = () =>
            {
                if (Interlocked.Exchange(ref confirmed, 1) == 0 && Interlocked.Decrement(ref remaining) == 0) confirm();
            } };
        }).ToArray();
    }
}
