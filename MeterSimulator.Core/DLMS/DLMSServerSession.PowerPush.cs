using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;

namespace MeterSimulator.DLMS;

public partial class DLMSServerSession
{
    public const string PowerPushLogicalName = "0.10.25.9.0.255";
    private const string PowerProfileLogicalName = "0.0.99.98.2.255";
    private const string PowerEventLogicalName = "0.0.96.11.2.255";
    private const string PowerClockLogicalName = "0.0.1.0.0.255";
    private const string PowerSequenceLogicalName = "0.0.96.15.2.255";

    private static GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>[]? PowerCaptures(GXDLMSObjectCollection objects)
    {
        var declared = objects.OfType<GXDLMSPushSetup>().FirstOrDefault(p => p.LogicalName == PowerPushLogicalName && p.PushObjectList.Count > 0);
        return declared is not null
            ? declared.PushObjectList.Where(c => c.Key.LogicalName != DeviceIdLN && c.Key.LogicalName != PowerPushLogicalName).ToArray()
            : (objects.FindByLN(ObjectType.ProfileGeneric, PowerProfileLogicalName) as GXDLMSProfileGeneric)?.CaptureObjects.ToArray();
    }

    public static bool CanBuildPowerPush(GXDLMSObjectCollection objects)
    {
        var captures = PowerCaptures(objects);
        // Power events carry a fresh RTC and UInt16 event code, never a historical buffer row.
        return captures is { Length: 2 or 3 }
            && captures[0].Key is GXDLMSClock && captures[0].Key.LogicalName == PowerClockLogicalName
            && captures[1].Key is GXDLMSData && captures[1].Key.LogicalName == PowerEventLogicalName
            && captures.All(c => c.Value.AttributeIndex == 2 && c.Value.DataIndex == 0)
            && (captures.Length == 2 || captures[2].Key is GXDLMSData && captures[2].Key.LogicalName == PowerSequenceLogicalName
                && PowerSequenceValue(objects) is not null);
    }

    private static object? PowerSequenceValue(GXDLMSObjectCollection objects)
    {
        if (objects.FindByLN(ObjectType.Data, PowerSequenceLogicalName) is GXDLMSData { Value: not null } counter) return counter.Value;
        var profile = objects.FindByLN(ObjectType.ProfileGeneric, PowerProfileLogicalName) as GXDLMSProfileGeneric;
        int index = profile?.CaptureObjects.FindIndex(c => c.Key.LogicalName == PowerSequenceLogicalName) ?? -1;
        return index < 0 ? null : profile!.Buffer.LastOrDefault(row => row.Length > index)?[index];
    }

    private byte[] BuildPowerPush(bool ciphering, ushort eventId, DateTimeOffset timestamp)
    {
        if (eventId is not (101 or 102)) throw new ArgumentOutOfRangeException(nameof(eventId));
        if (!CanBuildPowerPush(_objectsFromFile)) throw new NotSupportedException("Template has no supported power-event capture definition.");
        var push = new GXDLMSPushSetup(PowerPushLogicalName);
        var identity = new GXDLMSData(DeviceIdLN) { Value = _meter.GetValue(DeviceIdLN) ?? _meter.MeterNo };
        push.PushObjectList.Add(new(identity, new GXDLMSCaptureObject(2, 0)));
        push.PushObjectList.Add(new(push, new GXDLMSCaptureObject(1, 0)));
        var clock = new GXDLMSClock(PowerClockLogicalName) { Time = new GXDateTime(timestamp.UtcDateTime) };
        var code = new GXDLMSData(PowerEventLogicalName) { Value = eventId };
        code.SetDataType(2, DataType.UInt16);
        push.PushObjectList.Add(new(clock, new GXDLMSCaptureObject(2, 0)));
        push.PushObjectList.Add(new(code, new GXDLMSCaptureObject(2, 0)));
        var captures = PowerCaptures(_objectsFromFile)!;
        if (captures.Length == 3)
        {
            var source = (GXDLMSData)captures[2].Key;
            var sequence = new GXDLMSData(PowerSequenceLogicalName) { Value = _meter.GetValue(PowerSequenceLogicalName) ?? PowerSequenceValue(_objectsFromFile) };
            sequence.SetDataType(2, source.GetDataType(2) is DataType.None ? GXDLMSConverter.GetDLMSDataType(sequence.Value) : source.GetDataType(2));
            push.PushObjectList.Add(new(sequence, new GXDLMSCaptureObject(2, 0)));
        }
        lock (PushEncodeLock)
        {
            ConfigureNotifyCiphering(ciphering);
            return Concat(Notify.GeneratePushSetupMessages(timestamp.UtcDateTime, push));
        }
    }
}
