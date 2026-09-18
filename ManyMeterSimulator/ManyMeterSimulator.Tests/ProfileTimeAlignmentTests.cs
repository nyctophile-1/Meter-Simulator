using System.Globalization;
using System.Xml.Linq;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Tests;

public class ProfileTimeAlignmentTests
{
    [Theory]
    [InlineData("1.0.99.1.0.255", -48)]
    [InlineData("1.0.99.1.0.255", 48)]
    [InlineData("1.0.99.2.0.255", -48)]
    [InlineData("1.0.99.2.0.255", 48)]
    public void LoadingAlignsPastAndFutureSnapshotsWithoutChangingRowSpacing(string logicalName, int hours)
    {
        string path = Path.Combine(Path.GetTempPath(), "time-alignment-" + Guid.NewGuid().ToString("N") + ".xml");
        var objects = GXDLMSObjectCollection.Load(Path.Combine(AppContext.BaseDirectory, "Templates", "D1_Master.xml"));
        var source = (GXDLMSProfileGeneric)objects.FindByLN(ObjectType.ProfileGeneric, logicalName);
        var values = source.Buffer.Select(row => row.Skip(1).ToArray()).ToArray();
        var xml = XDocument.Load(Path.Combine(AppContext.BaseDirectory, "Templates", "D1_Master.xml"));
        var rows = xml.Root!.Elements("GXDLMSProfileGeneric").Single(p => p.Element("LN")!.Value == logicalName)
            .Element("Buffer")!.Elements("Row").ToArray();
        var anchor = DateTime.UtcNow.AddHours(hours);
        for (int i = 0; i < rows.Length; i++)
            rows[i].Elements("Cell").First().Value = anchor.AddMinutes(-30 * i).ToString("MM/dd/yyyy HH:mm:ss", CultureInfo.InvariantCulture);
        try
        {
            xml.Save(path);
            var loaded = new GXDLMSObjectCollection();
            var before = DateTimeOffset.UtcNow.AddSeconds(-2);
            new MeterObjectLoader(path).Load(loaded);
            var profile = (GXDLMSProfileGeneric)loaded.FindByLN(ObjectType.ProfileGeneric, logicalName);
            AssertAligned(profile, before);
            Assert.Equal(values.Length, profile.Buffer.Count);
            for (int i = 0; i < values.Length; i++)
                Assert.Equal(values[i], profile.Buffer[i].Skip(1).ToArray());
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(-2)]
    [InlineData(2)]
    public void PushRealignsSharedBufferAfterClockDriftInEitherDirection(int hours)
    {
        string path = Path.Combine(Path.GetTempPath(), "push-time-" + Guid.NewGuid().ToString("N") + ".xml");
        File.Copy(Path.Combine(AppContext.BaseDirectory, "Templates", "D1_Master.xml"), path);
        var server = new DLMSServerSession(new DLMSMeter(936, "1.0.0.0.0.255", 16, 1), path);
        try
        {
            server.Initialize(true);
            var profile = (GXDLMSProfileGeneric)server.Items.FindByLN(ObjectType.ProfileGeneric, "1.0.99.1.0.255");
            var anchor = DateTime.UtcNow.AddHours(hours);
            for (int i = 0; i < profile.Buffer.Count; i++)
                profile.Buffer[i][0] = new GXDateTime(anchor.AddMinutes(-30 * i));
            var before = DateTimeOffset.UtcNow.AddSeconds(-2);
            Assert.NotEmpty(server.BuildPushPayloads(false, "0.5.25.9.0.255"));
            AssertAligned(profile, before);
        }
        finally { server.Reset(); File.Delete(path); }
    }

    private static void AssertAligned(GXDLMSProfileGeneric profile, DateTimeOffset before)
    {
        var times = profile.Buffer.Select(row => Assert.IsType<GXDateTime>(row[0]).Value).ToArray();
        var after = DateTimeOffset.UtcNow.AddSeconds(2);
        if (profile.LogicalName == "1.0.99.1.0.255")
        {
            long ticks = profile.CapturePeriod * TimeSpan.TicksPerSecond;
            before = new DateTimeOffset(before.Ticks - before.Ticks % ticks, before.Offset);
            after = new DateTimeOffset(after.Ticks - after.Ticks % ticks, after.Offset);
            Assert.All(times, time => Assert.Equal(0, time.Ticks % ticks));
        }
        Assert.InRange(times.Max(), before, after);
        for (int i = 1; i < times.Length; i++)
            Assert.Equal(TimeSpan.FromMinutes(30), times[i - 1] - times[i]);
    }
}
