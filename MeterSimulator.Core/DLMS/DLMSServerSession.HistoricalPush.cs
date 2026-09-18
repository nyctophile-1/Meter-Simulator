using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;

namespace MeterSimulator.DLMS;

public partial class DLMSServerSession
{
    public int BlockPushPeriodSeconds => _objectsFromFile.FindByLN(ObjectType.ProfileGeneric, "1.0.99.1.0.255")
        is GXDLMSProfileGeneric { CapturePeriod: > 0 } profile
            ? checked((int)profile.CapturePeriod)
            : throw new InvalidOperationException("Block load requires a profile with a positive capture period.");

    // Project only onto the encoding graph under PushEncodeLock; never rewind live meter state or buffers.
    private void ProjectPushReading(GXDLMSPushSetup push, DateTimeOffset timestamp)
    {
        if (push.LogicalName is not (InstantDispatchLN or "0.5.25.9.0.255"))
            throw new InvalidOperationException("Historical push supports instantaneous and block load only.");
        object[]? row = null;
        GXDLMSProfileGeneric? profile = null;
        if (push.LogicalName == "0.5.25.9.0.255")
        {
            int seconds = BlockPushPeriodSeconds;
            timestamp = DateTimeOffset.FromUnixTimeSeconds(timestamp.ToUnixTimeSeconds() / seconds * seconds);
            profile = (GXDLMSProfileGeneric)_objectsFromFile.FindByLN(ObjectType.ProfileGeneric, "1.0.99.1.0.255");
            lock (profile.Buffer)
            {
                var rows = profile.Buffer.Where(r => r.Length >= profile.CaptureObjects.Count && r[0] is GXDateTime)
                    .OrderBy(r => ((GXDateTime)r[0]).Value).ToArray();
                if (rows.Length == 0) throw new InvalidOperationException("Block load has no complete seed row.");
                row = rows.FirstOrDefault(r => ((GXDateTime)r[0]).Value.ToUnixTimeSeconds() / seconds == timestamp.ToUnixTimeSeconds() / seconds);
                // Beyond retained history, repeat the template samples on the capture grid.
                long slot = (timestamp.ToUnixTimeSeconds() - ((GXDateTime)rows[0][0]).Value.ToUnixTimeSeconds()) / seconds;
                row ??= rows[(int)((slot % rows.Length + rows.Length) % rows.Length)];
                row = row.ToArray();
            }
        }
        foreach (var capture in push.PushObjectList)
        {
            if (capture.Key is GXDLMSClock clock) { clock.Time = new GXDateTime(timestamp.UtcDateTime); continue; }
            if (profile is null || row is null) continue;
            int column = profile.CaptureObjects.FindIndex(c => c.Key.LogicalName == capture.Key.LogicalName
                && c.Value.AttributeIndex == capture.Value.AttributeIndex);
            if (column < 1) continue;
            if (capture.Key is GXDLMSRegister register) register.Value = row[column];
            else if (capture.Key is GXDLMSData data) data.Value = row[column];
        }
    }
}
