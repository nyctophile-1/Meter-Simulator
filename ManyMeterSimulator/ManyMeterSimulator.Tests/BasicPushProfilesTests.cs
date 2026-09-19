using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Xml.Linq;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.KimbalSpecifics.Kmesh;
using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.Nic;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Microsoft.Extensions.Options;
using ProtoBuf;
using Task = System.Threading.Tasks.Task;

namespace ManyMeterSimulator.Tests;

public class BasicPushProfilesTests
{
    internal static readonly string[] Profiles = ["0.0.25.9.0.255", "0.5.25.9.0.255", MqttPushProfiles.Daily, MqttPushProfiles.Esw];

    [Theory]
    [InlineData("HP_Template_111.xml")]
    [InlineData("SA1231166HP_values.xml")]
    [InlineData("D1_Master.xml")]
    [InlineData("Template-31-D2.xml")]
    [InlineData("Values_SZ0000014HP.xml")]
    public void DiscoveryAndEncodingAgreeForFourBasicProfiles(string template)
    {
        string path = Path.Combine(AppContext.BaseDirectory, "Templates", template);
        var session = new DLMSServerSession(new DLMSMeter(700, "1.0.0.0.0.255", 16, 1), path);
        session.Initialize(true);
        Assert.Equal(session.GetPushSetupLogicalNames().Order(), MqttPushProfiles.ReadTemplate(path).Select(p => p.LogicalName).Order());
        foreach (string profile in Profiles)
        {
            Assert.Contains(profile, session.GetPushSetupLogicalNames());
            var fields = DailyPushTests.Decode(Assert.Single(session.BuildPushPayloads(false, profile)));
            Assert.Equal(profile.Split('.').Select(byte.Parse).ToArray(), Assert.IsType<byte[]>(fields[1]));
            Assert.True(fields.Length > 3);
        }
    }

    [Fact]
    public void MissingPushDeclarationsStillProduceBasicAndPowerProfiles()
    {
        var xml = XDocument.Load(Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        xml.Descendants("GXDLMSPushSetup").Remove();
        string path = Path.Combine(Path.GetTempPath(), $"maya-fallback-{Guid.NewGuid():N}.xml");
        try
        {
            xml.Save(path);
            var session = new DLMSServerSession(new DLMSMeter(701, "1.0.0.0.0.255", 16, 1), path);
            session.Initialize(true);
            Assert.Equal(Profiles.Append(MqttPushProfiles.Power).Order(), MqttPushProfiles.ReadTemplate(path).Select(p => p.LogicalName).Order());
            var frames = session.BuildPushPayloads(false);
            Assert.Equal(5, frames.Count);
            var fields = frames.Select(DailyPushTests.Decode).ToArray();
            Assert.Equal(Profiles.Append(MqttPushProfiles.Power).Order(), fields.Select(f => string.Join('.', (byte[])f[1])).Order());
            Assert.All(fields, f => Assert.Equal("CRY" + MeterIdentity.Serial(701), f[0]));
            Assert.Equal(session.GetEventStatusWord(), fields.Single(f => ((byte[])f[1])[1] == 4)[3].ToString());
        }
        finally { File.Delete(path); }
    }
}

public partial class MqttPushRunTests
{
    public static IEnumerable<object[]> BasicMqttCases() =>
        from nic in new[] { NicType.Mqtt4G, NicType.Mqtt4GImg, NicType.MqttKmesh }
        from profile in BasicPushProfilesTests.Profiles.Append(MqttPushProfiles.Power)
        from prepared in new[] { false, true }
        select new object[] { nic, profile, prepared };

    [Theory]
    [MemberData(nameof(BasicMqttCases))]
    public async Task FourBasicProfilesUseDlmsForEveryNonWirepasMqttNic(NicType nic, string profile, bool prepared)
    {
        var f = new Fixture(1);
        var batch = f.Batches.AddBatch("DLMS", "HP_Template_111.xml", 1, nic, null, "local");
        f.Batches.TryStart(batch.Id);
        await using var run = await f.Push.OpenMqttRunAsync(f.Request with { BatchIds = [batch.Id], PushSetupLogicalName = profile });
        if (prepared) { await run.PrepareAsync(); Assert.Empty(f.Publisher.Messages); await run.FireAsync(); }
        else Assert.Equal(1, (await run.SendLiveAsync()).MetersSent);
        var message = Assert.Single(f.Publisher.Messages);
        byte[] payload = message.Payload;
        if (nic == NicType.MqttKmesh)
        {
            Assert.Contains("gateway/push/meter/", message.Topic);
            payload = PushDataMessage.Parser.ParseFrom(payload).Data.Payload.ToByteArray();
        }
        else Assert.StartsWith("Normal_Push/", message.Topic);
        var fields = DailyPushTests.Decode(payload);
        Assert.Equal(profile.Split('.').Select(byte.Parse).ToArray(), Assert.IsType<byte[]>(fields[1]));
    }

    public static IEnumerable<object[]> BasicWirepasCases() =>
        from entry in new[] { (501, "1P"), (702, "3P"), (803, "CT") }
        from profile in BasicPushProfilesTests.Profiles.Append(MqttPushProfiles.Power)
        from prepared in new[] { false, true }
        select new object[] { entry.Item1, entry.Item2, profile, prepared };

    [Theory]
    [MemberData(nameof(BasicWirepasCases))]
    public async Task FourBasicProfilesAlwaysUseCustomWirepas(int id, string category, string profile, bool prepared)
    {
        var (model, options) = CustomPushEncoderTests.Fixture(id, category);
        var f = new Fixture(1, template: "HP_Template_111.xml", customTemplateId: id,
            encoder: new CustomPushEncoder(model, Options.Create(options)));
        await using var run = await f.Push.OpenMqttRunAsync(f.Request with { PushSetupLogicalName = profile });
        if (prepared) { await run.PrepareAsync(); Assert.Empty(f.Publisher.Messages); await run.FireAsync(); }
        else Assert.Equal(1, (await run.SendLiveAsync()).MetersSent);
        var message = Assert.Single(f.Publisher.Messages);
        Assert.EndsWith("/10/10", message.Topic);
        var packet = Serializer.Deserialize<GenericMessage>(new MemoryStream(message.Payload)).wirepas.packet_received_event.payload;
        Assert.Equal((uint)(id + 123456), BinaryPrimitives.ReadUInt32LittleEndian(packet));
        Assert.Equal(packet.Length, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(4)));
        Assert.Equal(profile switch { "0.0.25.9.0.255" => 1, "0.5.25.9.0.255" => 6, MqttPushProfiles.Daily => 7, MqttPushProfiles.Power => 11, _ => 5 }, packet[12]);
    }

    [Fact]
    public async Task MixedNicsUseTheirOwnFormatForTheSameBasicProfileWithDefaultHeader()
    {
        var f = new Fixture(1, template: "HP_Template_111.xml");
        var wirepas = f.Batches.AddBatch("default header", "HP_Template_111.xml", 1, NicType.MqttWirepas, 93, "local");
        var dlms = f.Batches.AddBatch("DLMS", "HP_Template_111.xml", 1, NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(wirepas.Id);
        f.Batches.TryStart(dlms.Id);
        await using var run = await f.Push.OpenMqttRunAsync(f.Request with
            { BatchIds = [wirepas.Id, dlms.Id], PushSetupLogicalName = MqttPushProfiles.Daily });
        Assert.Equal(2, (await run.SendLiveAsync()).MetersSent);
        var custom = Assert.Single(f.Publisher.Messages, m => m.Topic.EndsWith("/10/10"));
        Assert.Equal(7, Serializer.Deserialize<GenericMessage>(new MemoryStream(custom.Payload)).wirepas.packet_received_event.payload[12]);
        var direct = Assert.Single(f.Publisher.Messages, m => m.Topic.StartsWith("Normal_Push/"));
        Assert.Equal(new byte[] { 0, 6, 25, 9, 0, 255 }, DailyPushTests.Decode(direct.Payload)[1]);
    }

    [Fact]
    public async Task WirepasWithoutCustomMetadataNeverFallsBackToDlms()
    {
        var f = new Fixture(1, template: "HP_Template_111.xml");
        var batch = f.Batches.AddBatch("unmapped", "HP_Template_111.xml", 1, NicType.MqttWirepas, null, "local");
        f.Batches.TryStart(batch.Id);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => f.Push.OpenMqttRunAsync(f.Request with
            { BatchIds = [batch.Id], PushSetupLogicalName = "0.5.25.9.0.255" }));
        Assert.Contains("HES template", ex.Message);
        Assert.Empty(f.Publisher.Messages);
    }
}

public partial class TcpStressIntegrationTests
{
    [Theory]
    [InlineData("0.0.25.9.0.255")]
    [InlineData("0.5.25.9.0.255")]
    [InlineData("0.6.25.9.0.255")]
    [InlineData("0.4.25.9.0.255")]
    public async Task TcpAcceptsAndSendsFourBasicProfilesWithoutExplicitBlockSetup(string profile)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var f = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port, "HP_Template_111.xml");
        await using var run = await f.Push.OpenTcpRunAsync(f.Request with { PushSetupLogicalName = profile }, timeout.Token);
        var sending = run.SendLiveAsync();
        using var client = await listener.AcceptTcpClientAsync(timeout.Token);
        Assert.Equal(IPAddress.IPv6Loopback, ((IPEndPoint)client.Client.RemoteEndPoint!).Address);
        using var bytes = new MemoryStream();
        await client.GetStream().CopyToAsync(bytes, timeout.Token);
        Assert.Equal(1, (await sending).MetersSent);
        Assert.Equal(profile.Split('.').Select(byte.Parse).ToArray(), DailyPushTests.Decode(bytes.ToArray())[1]);
    }
}
