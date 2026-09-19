using System.Buffers.Binary;
using System.Text;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Secure;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.Mqtt;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Microsoft.Extensions.Options;
using ProtoBuf;
using Task = System.Threading.Tasks.Task;

namespace ManyMeterSimulator.Tests;

public class PowerPushTests
{
    [Theory]
    [InlineData("SA1231166HP_values.xml", false)]
    [InlineData("SA1231166HP_values.xml", true)]
    [InlineData("Template-31-D2.xml", false)]
    [InlineData("D1_Master.xml", true)]
    public void DlmsUsesFreshRtcAndExplicitCodeWithoutChangingTheTemplate(string template, bool ciphering)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Templates", template);
        var model = TemplateModelCache.Shared.Get(path);
        Assert.True(DLMSServerSession.CanBuildPowerPush(model));
        var meter = new DLMSMeter(813, "1.0.0.0.0.255", 16, 1);
        var session = new DLMSServerSession(meter, path);
        session.Initialize(true);
        var now = new DateTimeOffset(2026, 9, 19, 9, 17, 23, TimeSpan.Zero);
        Assert.Contains(MqttPushProfiles.Power, session.GetPushSetupLogicalNames());
        foreach (ushort eventId in new ushort[] { 101, 102, 101 })
        {
            var fields = Decode(Assert.Single(session.BuildPushPayloads(ciphering, MqttPushProfiles.Power, now, eventId)));
            Assert.Equal(template == "Template-31-D2.xml" ? 5 : 4, fields.Length);
            Assert.Equal("CRY" + MeterIdentity.Serial(813), fields[0]);
            Assert.Equal(new byte[] { 0, 10, 25, 9, 0, 255 }, Assert.IsType<byte[]>(fields[1]));
            byte[] rtc = Assert.IsType<byte[]>(fields[2]);
            Assert.Equal(2026, BinaryPrimitives.ReadUInt16BigEndian(rtc));
            Assert.Equal(new byte[] { 9, 19 }, rtc[2..4]);
            Assert.Equal(new byte[] { 9, 17, 23 }, rtc[5..8]);
            Assert.Equal(eventId, Assert.IsType<ushort>(fields[3]));
        }
        Assert.Throws<ArgumentOutOfRangeException>(() => session.BuildPushPayloads(false, MqttPushProfiles.Power, now, 103));
        var all = session.BuildPushPayloads(ciphering);
        Assert.Single(all.Select(Decode), fields => fields[1] is byte[] ln && ln.SequenceEqual(new byte[] { 0, 10, 25, 9, 0, 255 }));
    }

    [Theory]
    [InlineData("1P")]
    [InlineData("3P")]
    [InlineData("CT")]
    public void CustomPowerUsesBothIdsAndMetadataForEachLayout(string category)
    {
        var (model, options) = CustomPushEncoderTests.Fixture(501, category);
        options.EventIds.Clear();
        var encoder = new CustomPushEncoder(model, Options.Create(options));
        Assert.Contains(encoder.GetProfiles(501), p => p.Key == MqttPushProfiles.CustomPower);
        var now = DateTimeOffset.FromUnixTimeSeconds(1_789_999_999);
        foreach (ushort id in new ushort[] { 101, 102 })
        {
            var packet = encoder.Encode(501, MqttPushProfiles.CustomPower, 813, 19, now,
                _ => new GXDateTime(now.UtcDateTime), powerEventId: id);
            Assert.Equal(11, packet[12]);
            Assert.Equal(813u, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(16)));
            Assert.Equal(now.ToUnixTimeSeconds() + 330 * 60, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(23)));
            Assert.Equal(id, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(27)));
            Assert.Equal(29, packet.Length);
        }
        // 102 requiring a different layout must be checked too.
        options.EventsWithPowerProfile = [102];
        Assert.Equal(3, encoder.GetFields(501, MqttPushProfiles.CustomPower, 102).Count);
        options.EventsWithPowerProfile = null;
        Assert.DoesNotContain(encoder.GetProfiles(501), p => p.Key == MqttPushProfiles.CustomPower);
    }

    [Fact]
    public async Task SequenceSerializesOnlyTheSameMeterAndCancelledWaitDoesNotAdvance()
    {
        var sequence = new PowerEventSequence();
        using var first = await sequence.AcquireAsync(1, default);
        using var other = await sequence.AcquireAsync(2, default);
        using var stop = new CancellationTokenSource();
        var waiting = sequence.AcquireAsync(1, stop.Token).AsTask();
        Assert.False(waiting.IsCompleted);
        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.Equal(101, sequence.Next(1));
        sequence.Confirm(1, 101);
        Assert.Equal(102, sequence.Next(1));
        Assert.Equal(101, sequence.Next(2));
    }

    internal static object[] Decode(byte[] payload)
    {
        var client = new GXDLMSSecureClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        client.Ciphering.Security = Security.Encryption;
        client.Ciphering.BlockCipherKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
        client.Ciphering.AuthenticationKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
        var data = new GXReplyData();
        var notify = new GXReplyData();
        client.GetData(new GXByteBuffer(payload), data, notify);
        return Assert.IsAssignableFrom<IEnumerable<object>>(notify.Value ?? data.Value).ToArray();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PoolConfirmsSuccessfulEventDespiteOtherFailureOrCancellation(bool cancel)
    {
        var sequence = new PowerEventSequence();
        using var stop = new CancellationTokenSource();
        var connection = new PowerConnection((message, _) =>
        {
            if (message.Topic == "reject") return Task.FromResult(false);
            if (message.Topic == "cancel") { stop.Cancel(); throw new OperationCanceledException(stop.Token); }
            return Task.FromResult(true);
        });
        await using var pool = await MqttPushPool.OpenAsync([connection], 1, TimeSpan.FromSeconds(2), default);
        NicPublish[] messages = [new("reject", []), new("power", []) { DeliveryConfirmed = () => sequence.Confirm(1, 101) }, new(cancel ? "cancel" : "reject", [])];
        if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pool.PublishMeterAsync(messages, stop.Token));
        else
        {
            var result = await pool.PublishMeterAsync(messages, stop.Token);
            Assert.Equal(1, result.Sent);
            Assert.Equal(2, result.Failed);
        }
        Assert.Equal(102, sequence.Next(1));
        await pool.PublishMeterAsync([new("reject", []) { DeliveryConfirmed = () => sequence.Confirm(1, 102) }], default);
        Assert.Equal(102, sequence.Next(1));
    }

    private sealed class PowerConnection(Func<NicPublish, CancellationToken, Task<bool>> publish) : IMqttPushConnection
    {
        public bool IsConnected => true;
        public Task ConnectAsync(CancellationToken token) => Task.CompletedTask;
        public Task<bool> PublishAsync(NicPublish message, int qos, CancellationToken token) => publish(message, token);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

public partial class MqttPushRunTests
{
    private static Fixture PowerFixture(int count = 1)
    {
        var (model, options) = CustomPushEncoderTests.Fixture(93, "1P");
        return new Fixture(count, template: "SA1231166HP_values.xml", encoder: new CustomPushEncoder(model, Options.Create(options)));
    }

    private static ushort CustomPowerCode(NicPublish message)
    {
        var packet = Serializer.Deserialize<GenericMessage>(new MemoryStream(message.Payload)).wirepas.packet_received_event.payload;
        return BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(27));
    }

    [Fact]
    public async Task PowerNormalAlternatesOnlyOnSuccessAndStressPreparationIsIndependent()
    {
        var f = PowerFixture();
        async Task Normal() => Assert.Equal(1, (await f.Push.PushBatchAsync(f.Batch.Id, pushSetupLogicalName: MqttPushProfiles.Power)).Sent);
        await Normal();
        await using (var discarded = await f.Push.OpenMqttRunAsync(f.Request with { PushSetupLogicalName = MqttPushProfiles.Power }))
            await discarded.PrepareAsync();
        await using (var prepared = await f.Push.OpenMqttRunAsync(f.Request with { PushSetupLogicalName = MqttPushProfiles.CustomPower }))
        {
            await prepared.PrepareAsync();
            await prepared.FireAsync();
        }
        f.Publisher.Reject = true;
        Assert.Equal(1, (await f.Push.PushBatchAsync(f.Batch.Id, pushSetupLogicalName: MqttPushProfiles.Power)).Failed);
        f.Publisher.Reject = false;
        await Normal();
        await Normal();
        Assert.Equal(new ushort[] { 101, 101, 102, 102, 101 }, f.Publisher.Messages.Select(CustomPowerCode));
    }

    [Fact]
    public async Task OverlappingNormalPowerPushesAlternatePerMeter()
    {
        var f = PowerFixture(2);
        f.Publisher.BeforePublish = ct => Task.Delay(10, ct);
        await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => f.Push.PushBatchAsync(f.Batch.Id, pushSetupLogicalName: MqttPushProfiles.Power)));
        foreach (var meter in f.Publisher.Messages.GroupBy(m => m.Topic))
            Assert.Equal(new ushort[] { 101, 102, 101, 102 }, meter.Select(CustomPowerCode));
        // Event 101 never suppresses the next ordinary profile in wave one.
        Assert.Equal(2, (await f.Push.PushBatchAsync(f.Batch.Id, pushSetupLogicalName: MqttPushProfiles.CustomDaily)).Sent);
    }

    [Fact]
    public async Task PowerStressLoopsAlternateAndNewRunStartsAt101()
    {
        var f = PowerFixture();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        f.Publisher.AfterPublish = () => { if (f.Publisher.Messages.Count == 3) stop.Cancel(); };
        await using (var run = await f.Push.OpenMqttRunAsync(f.Request with { PushSetupLogicalName = MqttPushProfiles.Power }, stop.Token))
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.SendLoopAsync(new()));
        f.Publisher.AfterPublish = null;
        await using (var run = await f.Push.OpenMqttRunAsync(f.Request with { PushSetupLogicalName = MqttPushProfiles.Power }))
            await run.SendLiveAsync();
        Assert.Equal(new ushort[] { 101, 102, 101, 101 }, f.Publisher.Messages.Select(CustomPowerCode));
    }

    [Fact]
    public async Task DlmsNormalPowerAlternatesIndependentlyFromCustomAndStress()
    {
        var f = PowerFixture();
        var batch = f.Batches.AddBatch("DLMS", "SA1231166HP_values.xml", 1, ManyMeterSimulator.Networking.Nic.NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(batch.Id);
        for (int i = 0; i < 3; i++)
            Assert.Equal(1, (await f.Push.PushBatchAsync(batch.Id, pushSetupLogicalName: MqttPushProfiles.Power)).Sent);
        Assert.Equal(new ushort[] { 101, 102, 101 }, f.Publisher.Messages.Select(m => (ushort)PowerPushTests.Decode(m.Payload)[3]));
    }
}

public partial class TcpStressIntegrationTests
{
    [Fact]
    public async Task PowerTcpPreparedAndNormalPushesUseSeparateSequences()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.IPv6Loopback, 0);
        listener.Start();
        var f = new Fixture(((System.Net.IPEndPoint)listener.LocalEndpoint).Port);
        async Task<ushort> Receive()
        {
            using var client = await listener.AcceptTcpClientAsync(timeout.Token);
            using var bytes = new MemoryStream();
            await client.GetStream().CopyToAsync(bytes, timeout.Token);
            return (ushort)PowerPushTests.Decode(bytes.ToArray())[3];
        }
        await using (var discarded = await f.Push.OpenTcpRunAsync(f.Request with { PushSetupLogicalName = MqttPushProfiles.Power }, timeout.Token))
            await discarded.PrepareAsync();
        Assert.False(listener.Pending());
        await using (var prepared = await f.Push.OpenTcpRunAsync(f.Request with { PushSetupLogicalName = MqttPushProfiles.Power }, timeout.Token))
        {
            await prepared.PrepareAsync();
            var receiving = Receive();
            Assert.Equal(1, (await prepared.FireAsync()).MessagesSent);
            Assert.Equal(101, await receiving);
        }
        foreach (ushort expected in new ushort[] { 101, 102, 101 })
        {
            var receiving = Receive();
            Assert.Equal(1, (await f.Push.PushBatchAsync(f.Batch.Id, cancellationToken: timeout.Token, pushSetupLogicalName: MqttPushProfiles.Power)).Sent);
            Assert.Equal(expected, await receiving);
        }
        await using var loop = await f.Push.OpenTcpRunAsync(f.Request with { PushSetupLogicalName = MqttPushProfiles.Power }, timeout.Token);
        var sending = loop.SendLoopAsync(new() { CyclePauseSeconds = 1 });
        Assert.Equal(101, await Receive());
        Assert.Equal(102, await Receive());
        timeout.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending);
    }
}
