using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;

namespace MeterSimulator.DLMS;

public partial class DLMSServerSession
{
    public const string DailyPushLogicalName = "0.6.25.9.0.255";
    private static readonly string[] DailyColumns = ["0.0.1.0.0.255", "1.0.1.8.0.255", "1.0.9.8.0.255", "1.0.2.8.0.255", "1.0.10.8.0.255"];

    public bool CanBuildDailyPush => FindDailyRow() is not null;

    private object[]? FindDailyRow()
    {
        if (_objectsFromFile.FindByLN(ObjectType.ProfileGeneric, "1.0.99.2.0.255") is not GXDLMSProfileGeneric profile)
            return null;
        var positions = DailyColumns.Select(ln => profile.CaptureObjects.FindIndex(c =>
            c.Key.LogicalName == ln && c.Value.AttributeIndex == 2 && c.Value.DataIndex == 0)).ToArray();
        if (positions.Any(p => p < 0)) return null;
        var row = profile.Buffer.Where(r => positions.All(p => p < r.Length && r[p] is not null)
                && r[positions[0]] is GXDateTime)
            .OrderByDescending(r => ((GXDateTime)r[positions[0]]).Value).FirstOrDefault();
        return row is null ? null : positions.Select(p => row[p]).ToArray();
    }

    private IReadOnlyList<byte[]> BuildDailyPush(bool useCiphering)
    {
        // Reuse the template's captured daily row and the HES flat daily-push field order.
        var row = FindDailyRow()
            ?? throw new InvalidOperationException("Daily profile has no complete timestamped row.");
        var push = new GXDLMSPushSetup(DailyPushLogicalName);
        var identity = new GXDLMSData(DeviceIdLN) { Value = _meter.GetValue(DeviceIdLN) ?? _meter.MeterNo };
        push.PushObjectList.Add(new(identity, new GXDLMSCaptureObject(2, 0)));
        push.PushObjectList.Add(new(push, new GXDLMSCaptureObject(1, 0)));
        var capturedTime = (GXDateTime)row[0];
        var pushTime = new GXDateTime(capturedTime.Value)
        {
            Skip = capturedTime.Skip & ~DateTimeSkips.Deviation,
            Extra = capturedTime.Extra,
            Status = capturedTime.Status,
            DayOfWeek = capturedTime.DayOfWeek
        };
        var rtc = new GXDLMSClock(DailyColumns[0]) { Time = pushTime };
        push.PushObjectList.Add(new(rtc, new GXDLMSCaptureObject(2, 0)));
        for (int i = 1; i < row.Length; i++)
        {
            var data = new GXDLMSData(DailyColumns[i]) { Value = row[i] };
            data.SetDataType(2, GXDLMSConverter.GetDLMSDataType(data.Value));
            push.PushObjectList.Add(new(data, new GXDLMSCaptureObject(2, 0)));
        }
        lock (PushEncodeLock)
        {
            ConfigureNotifyCiphering(useCiphering);
            return [Concat(Notify.GeneratePushSetupMessages(DateTime.UtcNow, push))];
        }
    }
}
