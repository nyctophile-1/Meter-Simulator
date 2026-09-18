using System.Collections;
using System.Buffers.Binary;
using System.Text;
using System.Xml.Linq;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Secure;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using ManyMeterSimulator.KimbalSpecifics.Kmesh;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.Nic;
using ProtoBuf;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Task = System.Threading.Tasks.Task;

namespace ManyMeterSimulator.Tests;

public class DailyPushTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DailyFallbackUsesHesChannelIdentityAndCapturedRowWithoutChangingOtherPushes(bool ciphering)
    {
        var session = new DLMSServerSession(new DLMSMeter(999, "1.0.0.0.0.255", 16, 1),
            Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        session.Initialize(true);
        var profiles = session.GetPushSetupLogicalNames();
        Assert.True(session.CanBuildDailyPush);
        Assert.Contains(MqttPushProfiles.Daily, profiles);
        var profile = Assert.IsType<GXDLMSProfileGeneric>(TemplateModelCache.Shared.Get(
            Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"))
            .FindByLN(ObjectType.ProfileGeneric, "1.0.99.2.0.255"));
        var row = profile.Buffer.OrderByDescending(r => ((GXDateTime)r[0]).Value).First();
        var capturedTime = (GXDateTime)row[0];
        var originalTime = (capturedTime.Value, capturedTime.Skip, capturedTime.Extra, capturedTime.Status, capturedTime.DayOfWeek);
        var frame = Assert.Single(session.BuildPushPayloads(ciphering, DLMSServerSession.DailyPushLogicalName));
        var values = Decode(frame);
        Assert.Equal(7, values.Length);
        Assert.Equal("CRY" + MeterIdentity.Serial(999), values[0]);
        Assert.Equal(new byte[] { 0, 6, 25, 9, 0, 255 }, Assert.IsType<byte[]>(values[1]));
        var rtc = Assert.IsType<byte[]>(values[2]);
        var expected = ((GXDateTime)row[0]).Value;
        Assert.Equal(0, BinaryPrimitives.ReadInt16BigEndian(rtc.AsSpan(9, 2)));
        Assert.Equal(expected.Year, BinaryPrimitives.ReadUInt16BigEndian(rtc));
        Assert.Equal(new[] { expected.Month, expected.Day, expected.Hour, expected.Minute, expected.Second },
            new[] { (int)rtc[2], rtc[3], rtc[5], rtc[6], rtc[7] });
        for (int i = 1; i < 5; i++) Assert.Equal(Convert.ToDouble(row[i]), Convert.ToDouble(values[i + 2]));
        var again = Assert.Single(session.BuildPushPayloads(ciphering, MqttPushProfiles.Daily));
        if (ciphering) Assert.NotEqual(frame, again);
        Assert.Equal(originalTime, (capturedTime.Value, capturedTime.Skip, capturedTime.Extra, capturedTime.Status, capturedTime.DayOfWeek));
        Assert.Equal(profiles, session.GetPushSetupLogicalNames());
    }

    [Theory]
    [InlineData("buffer")]
    [InlineData("capture")]
    [InlineData("attribute")]
    public void IncompleteDailyProfileIsNotAdvertised(string missing)
    {
        var xml = XDocument.Load(Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        var daily = xml.Descendants("GXDLMSProfileGeneric").Single(p => (string?)p.Element("LN") == "1.0.99.2.0.255");
        if (missing == "buffer") daily.Element("Buffer")!.RemoveNodes();
        else if (missing == "capture") daily.Element("CaptureObjects")!.Elements("Item").Last().Remove();
        else daily.Element("CaptureObjects")!.Elements("Item").Last().Element("Attribute")!.Value = "3";
        string path = Path.Combine(Path.GetTempPath(), "daily-" + Guid.NewGuid().ToString("N") + ".xml");
        try
        {
            xml.Save(path);
            Assert.DoesNotContain(MqttPushProfiles.ReadTemplate(path), p => p.LogicalName == MqttPushProfiles.Daily);
            var session = new DLMSServerSession(new DLMSMeter(999, "1.0.0.0.0.255", 16, 1), path);
            session.Initialize(true);
            Assert.False(session.CanBuildDailyPush);
            Assert.DoesNotContain(MqttPushProfiles.Daily, session.GetPushSetupLogicalNames());
        }
        finally { File.Delete(path); }
    }

    internal static object[] Decode(byte[] frame)
    {
        var client = new GXDLMSSecureClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        client.Ciphering.Security = Security.Encryption;
        client.Ciphering.BlockCipherKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
        client.Ciphering.AuthenticationKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
        var response = new GXReplyData();
        var notify = new GXReplyData();
        client.GetData(new GXByteBuffer(frame), response, notify);
        return Assert.IsAssignableFrom<IEnumerable>(notify.Value ?? response.Value).Cast<object>().ToArray();
    }
}

public partial class MqttPushRunTests
{
    [Theory]
    [InlineData(NicType.Mqtt4G, false)]
    [InlineData(NicType.Mqtt4GImg, false)]
    [InlineData(NicType.MqttKmesh, false)]
    [InlineData(NicType.Mqtt4G, true)]
    [InlineData(NicType.Mqtt4GImg, true)]
    [InlineData(NicType.MqttKmesh, true)]
    public async Task DailyDlmsPushUsesTheSamePayloadAcrossAllMqttNics(NicType nic, bool ciphering)
    {
        var f = new Fixture(1, ciphering, "SA1231166HP_values.xml");
        var batch = f.Batches.AddBatch("DLMS", "SA1231166HP_values.xml", 1, nic, null, "local");
        f.Batches.TryStart(batch.Id);
        await using var run = await f.Push.OpenMqttRunAsync(f.Request with
            { BatchIds = [batch.Id], PushSetupLogicalName = MqttPushProfiles.Daily });
        if (ciphering) await run.SendLiveAsync();
        else { await run.PrepareAsync(); Assert.Empty(f.Publisher.Messages); await run.FireAsync(); }
        var message = Assert.Single(f.Publisher.Messages);
        var meter = new MeterRef(batch.StartIndex, nic);
        byte[] payload = message.Payload;
        if (nic == NicType.MqttKmesh)
        {
            Assert.Equal($"gateway/push/meter/sim-gw/{meter.NodeId}", message.Topic);
            var packet = PushDataMessage.Parser.ParseFrom(payload);
            Assert.Equal(uint.Parse(meter.NodeId), packet.Header.NodeAddr);
            Assert.Equal(meter.Serial, packet.Data.MeterNumber);
            Assert.Equal(RequestType.KapDlmsWraperPushData, packet.Data.RespType);
            Assert.Equal(1u, packet.Data.FragInfo.TotalFrag);
            payload = packet.Data.Payload.ToByteArray();
        }
        else Assert.Equal($"Normal_Push/{meter.NodeId}", message.Topic);
        var fields = DailyPushTests.Decode(payload);
        Assert.Equal(7, fields.Length);
        Assert.Equal("CRY" + meter.Serial, fields[0]);
        Assert.Equal(new byte[] { 0, 6, 25, 9, 0, 255 }, Assert.IsType<byte[]>(fields[1]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CustomDailyPushDecodesWithHesProfileScalarAndClock(bool prepared)
    {
        var f = new Fixture(1);
        var before = DateTimeOffset.UtcNow.AddSeconds(-1);
        await using var run = await f.Push.OpenMqttRunAsync(f.Request);
        if (prepared) { await run.PrepareAsync(); await run.FireAsync(); }
        else await run.SendLiveAsync();
        var message = Assert.Single(f.Publisher.Messages);
        var bytes = Serializer.Deserialize<GenericMessage>(new MemoryStream(message.Payload)).wirepas.packet_received_event.payload;
        Assert.Equal(43, bytes.Length);
        Assert.Equal(Template93.MagicNumber, BinaryPrimitives.ReadUInt32LittleEndian(bytes));
        Assert.Equal(43, BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(4)));
        Assert.Equal(7, bytes[12]);
        var rtc = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(23))).AddMinutes(-330);
        Assert.InRange(rtc, before, DateTimeOffset.UtcNow);
        decimal import = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(27)) / 1000m;
        decimal apparent = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(31)) / 1000m;
        decimal export = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(35)) / 1000m;
        decimal exportApparent = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(39)) / 1000m;
        Assert.True(import > 0 && apparent >= import);
        Assert.InRange(Math.Abs(export - import * .05m), 0, .001m);
        Assert.InRange(Math.Abs(exportApparent - apparent * .05m), 0, .001m);
        Assert.Equal(0, f.Sessions.LiveMeterCount);
    }
}
