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
    [Fact]
    public async Task HistoricalMqttUsesFixedWindowAndStillValidatesPublisherSettings()
    {
        var now = new DateTimeOffset(2026, 9, 21, 12, 7, 23, TimeSpan.Zero);
        var end = now.AddDays(-2);
        var fixture = new Fixture(1, clock: new BlockClock(now));
        var batch = fixture.Batches.AddBatch("history", "D1_Master.xml", 1, NicType.Mqtt4G, null, "local");
        fixture.Batches.TryStart(batch.Id);

        var request = new HistoricalPushRequest
        {
            BatchIds = [batch.Id],
            Days = 1,
            EndTimeUtc = end,
            WaitForPeerCloseSeconds = 0,
            InstantaneousIntervalMinutes = 60,
            MaxConcurrency = 1,
            PublisherCount = 1
        };

        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Push.OpenHistoricalRunAsync(
            request with { PublisherCount = 2 }, default));
        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Push.OpenHistoricalRunAsync(
            request with { Qos = 3 }, default));
        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Push.OpenHistoricalRunAsync(
            request with { EndTimeUtc = now.AddSeconds(1) }, default));
        Assert.Empty(fixture.Publisher.Pools);

        await using var run = await fixture.Push.OpenHistoricalRunAsync(request, default);
        var result = await run.SendAsync(_ => { }, default);

        Assert.Equal(end, result.To);
        Assert.Equal(end.AddDays(-1), result.From);
        Assert.Equal(result.Total, result.Sent);
        Assert.All(fixture.Publisher.Messages, message => Assert.InRange(
            HistoricalPushTests.ReadTime(DailyPushTests.Decode(message.Payload)[2]), result.From, result.To));
    }

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
        await using var run = await f.Push.OpenHistoricalRunAsync(new()
        {
            BatchIds = [batch.Id], Days = 1, MaxConcurrency = 1, PublisherCount = 1
        }, default);
        f.Publisher.AfterPublish = () => f.Batches.TryStop(batch.Id);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.SendAsync(_ => { }, default));
        Assert.Single(f.Publisher.Messages);
    }
}

public partial class TcpStressIntegrationTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    public async Task HistoricalTcpUsesMeterSourceIpAndRealFramesForBothProfiles(int peerCloseWait)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var f = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port, "D1_Master.xml",
            HistoricalPushTests.Impaired(CommClass.Healthy), StressDelay());
        int period = f.Sessions.GetOrCreate(new MeterRef(f.Batch.StartIndex, f.Batch.NicType)).BlockPushPeriodSeconds;
        int expected = 24 + 86400 / period;

        var received = ReceiveAsync();
        var end = new DateTimeOffset(2026, 1, 2, 12, 7, 23, TimeSpan.FromHours(5.5));
        await using var run = await f.Push.OpenHistoricalRunAsync(new()
        {
            BatchIds = [f.Batch.Id],
            Days = 1,
            EndTimeUtc = end,
            WaitForPeerCloseSeconds = peerCloseWait,
            InstantaneousIntervalMinutes = 60,
            RecordsPerSecond = 300000,
            MaxConcurrency = 1,
            PublisherCount = 0,
            Qos = -1
        }, timeout.Token);
        var result = await run.SendAsync(_ => { }, timeout.Token);
        var records = await received;

        Assert.Equal(end.ToUniversalTime(), result.To);
        Assert.Equal(TimeSpan.Zero, result.To.Offset);
        Assert.Equal(end.AddDays(-1), result.From);
        Assert.Equal(expected, result.Sent);
        Assert.Equal(0, result.Failed);
        Assert.Equal(new byte[] { 0, 5 }, records.Select(r => ((byte[])r[1])[1]).Distinct().Order());
        Assert.All(records, r => Assert.InRange(HistoricalPushTests.ReadTime(r[2]), result.From, result.To));

        async Task<List<object[]>> ReceiveAsync()
        {
            var records = new List<object[]>();
            var clients = new List<TcpClient>();
            try
            {
                for (int i = 0; i < expected; i++)
                {
                    var client = await listener.AcceptTcpClientAsync(timeout.Token);
                    clients.Add(client);
                    Assert.Equal(IPAddress.IPv6Loopback, ((IPEndPoint)client.Client.RemoteEndPoint!).Address);
                    var stream = client.GetStream();
                    var header = new byte[8];
                    await stream.ReadExactlyAsync(header, timeout.Token);
                    var payload = new byte[BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(6))];
                    await stream.ReadExactlyAsync(payload, timeout.Token);
                    records.Add(DailyPushTests.Decode([.. header, .. payload]));

                    if (peerCloseWait == 0)
                    {
                        Assert.Equal(0, await stream.ReadAsync(new byte[1], timeout.Token));
                    }
                    else
                    {
                        if (i == 0)
                        {
                            using var probe = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
                            probe.CancelAfter(100);
                            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                            {
                                using var unexpected = await listener.AcceptTcpClientAsync(probe.Token);
                            });
                        }

                        client.Client.Shutdown(SocketShutdown.Send);
                        Assert.Equal(0, await stream.ReadAsync(new byte[1], timeout.Token));
                    }
                }
            }
            finally
            {
                foreach (var client in clients)
                {
                    client.Dispose();
                }
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
