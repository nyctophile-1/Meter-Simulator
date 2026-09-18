using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.SmartNic;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Options;
using ProtoBuf;

namespace ManyMeterSimulator.Tests;

public partial class MqttPushRunTests
{
    [Theory]
    [InlineData(15)]
    [InlineData(30)]
    public async Task HistoricalCustomUsesSharedTimestampGeneratorAndConfiguredBlockCadence(int minutes)
    {
        const int template = 817;
        var model = new HesDataModel();
        model.AddTemplate(new(template, "historical", 12, 12, 2, 2, false, 9, null, null, 10, null, null)
            { MeterProfileHeaderTemplateId = 3 });
        model.AddMagic(0x0011090E, template);
        foreach (var (id, profile, command) in new[] { (9, "BLOCK", 4), (10, "INSTANT", 3) })
        {
            model.AddField(id, profile + "_CUSTOM_PUSH_1P", new(1, "RtcDateTime", "DateTime", 0, 0, "1P", command));
            model.AddField(id, profile + "_CUSTOM_PUSH_1P", new(2, "CumulativeEnergyKwhImport", "UInt32", -3, 0, "1P", command));
        }
        model.Freeze();
        var encoder = new CustomPushEncoder(model, Options.Create(new CustomPushOptions { MeterCategories = new() { [template] = "1P" } }));
        var end = new DateTimeOffset(2026, 9, 18, 12, 7, 23, TimeSpan.Zero);
        var f = new Fixture(2, customTemplateId: template, encoder: encoder, clock: new BlockClock(end),
            customPullOptions: new() { BlockPeriodMinutesByTemplate = new() { [template] = minutes } });
        await using var run = await f.Push.OpenHistoricalRunAsync(new() { BatchIds = [f.Batch.Id], Days = 1,
            InstantaneousIntervalMinutes = 60, RecordsPerSecond = 300000 }, default);
        var result = await run.SendAsync(_ => { }, default);
        Assert.Equal(2 * (24 + 1440 / minutes), result.Sent);
        Assert.Equal(0, result.Failed);
        var instantaneous = new List<uint>();
        foreach (var message in f.Publisher.Messages)
        {
            using var stream = new MemoryStream(message.Payload);
            var packet = Serializer.Deserialize<GenericMessage>(stream).wirepas.packet_received_event.payload;
            var time = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(23))).AddMinutes(-330);
            Assert.InRange(time, end.AddDays(-1), end);
            uint energy = BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(27));
            if (packet[12] == 6)
            {
                Assert.Equal(0, time.ToUnixTimeSeconds() % (minutes * 60));
                Assert.Equal((uint)Math.Round(8000m * minutes / 1440m), energy);
            }
            else { Assert.Equal(1, packet[12]); instantaneous.Add(energy); }
        }
        Assert.True(instantaneous.Distinct().Count() > 2);
        Assert.Equal(0, f.Sessions.LiveMeterCount);
        Assert.Single(f.Publisher.Pools);
    }

    [Fact]
    public async Task HistoricalRunStopsWhenBatchChangesInsteadOfContinuingOnOldBroker()
    {
        var f = new Fixture(1);
        var batch = f.Batches.AddBatch("history", "D1_Master.xml", 1, NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(batch.Id);
        await using var run = await f.Push.OpenHistoricalRunAsync(new() { BatchIds = [batch.Id], Days = 1 }, default);
        f.Publisher.AfterPublish = () => f.Batches.TryStop(batch.Id);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.SendAsync(_ => { }, default));
        Assert.Single(f.Publisher.Messages);
    }
}

public partial class TcpStressIntegrationTests
{
    [Fact]
    public async Task HistoricalTcpUsesMeterSourceIpAndRealFramesForBothProfiles()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var f = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port, "D1_Master.xml",
            HistoricalPushTests.Impaired(CommClass.Healthy), StressDelay());
        int period = f.Sessions.GetOrCreate(new MeterRef(f.Batch.StartIndex, f.Batch.NicType)).BlockPushPeriodSeconds;
        int expected = 24 + 86400 / period;
        var received = ReceiveAsync();
        await using var run = await f.Push.OpenHistoricalRunAsync(new() { BatchIds = [f.Batch.Id], Days = 1,
            InstantaneousIntervalMinutes = 60, RecordsPerSecond = 300000 }, timeout.Token);
        var result = await run.SendAsync(_ => { }, timeout.Token);
        var records = await received;
        Assert.Equal(expected, result.Sent);
        Assert.Equal(0, result.Failed);
        Assert.Equal(new byte[] { 0, 5 }, records.Select(r => ((byte[])r[1])[1]).Distinct().Order());
        Assert.All(records, r => Assert.InRange(HistoricalPushTests.ReadTime(r[2]), result.From, result.To));

        async Task<List<object[]>> ReceiveAsync()
        {
            var records = new List<object[]>();
            for (int i = 0; i < expected; i++)
            {
                using var client = await listener.AcceptTcpClientAsync(timeout.Token);
                Assert.Equal(IPAddress.IPv6Loopback, ((IPEndPoint)client.Client.RemoteEndPoint!).Address);
                using var bytes = new MemoryStream();
                await client.GetStream().CopyToAsync(bytes, timeout.Token);
                records.Add(DailyPushTests.Decode(bytes.ToArray()));
            }
            return records;
        }
    }

    [Fact]
    public async Task OrdinaryAndScheduledTcpStillApplyBadCommBeforeOpeningSockets()
    {
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var f = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port, "D1_Master.xml",
            HistoricalPushTests.Impaired(CommClass.NonComm));
        Assert.Equal(0, (await f.Push.PushBatchAsync(f.Batch.Id)).Sent);
        await using var scheduled = await f.Push.OpenBatchTrafficAsync(f.Batch, BatchTrafficKind.Instantaneous, default);
        await Assert.ThrowsAsync<PushSkippedException>(() => scheduled.SendAsync(f.Batch.StartIndex, default));
        await using var history = await f.Push.OpenHistoricalRunAsync(new() { BatchIds = [f.Batch.Id], Days = 1, RecordsPerSecond = 300000 }, default);
        var result = await history.SendAsync(_ => { }, default);
        Assert.Equal(result.Total, result.Skipped);
        Assert.Equal(0, result.Sent);
        Assert.False(listener.Pending());
    }
}
