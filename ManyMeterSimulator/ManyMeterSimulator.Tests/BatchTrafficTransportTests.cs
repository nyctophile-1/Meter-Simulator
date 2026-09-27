using System.Collections;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using ManyMeterSimulator.Settings;
using Microsoft.Extensions.Options;
using Task = System.Threading.Tasks.Task;

namespace ManyMeterSimulator.Tests;

public partial class TcpStressIntegrationTests
{
    [Fact]
    public async Task ScheduledTcpPushBypassesSimulatedFailuresAndDelay()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var f = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port,
            badComm: HistoricalPushTests.Impaired(CommClass.NonComm), networkDelay: StressDelay());
        await using var session = await f.Push.OpenBatchTrafficAsync(f.Batch, BatchTrafficKind.Instantaneous, default);
        var sending = session.SendAsync(f.Batch.StartIndex, timeout.Token);
        using var client = await listener.AcceptTcpClientAsync(timeout.Token);
        using var received = new MemoryStream();
        await client.GetStream().CopyToAsync(received, timeout.Token);
        await sending;
        Assert.NotEmpty(received.ToArray());
    }

    [Theory]
    [InlineData(BatchTrafficKind.Instantaneous, 0)]
    [InlineData(BatchTrafficKind.BlockLoad, 5)]
    [InlineData(BatchTrafficKind.Daily, 6)]
    public async Task ScheduledTcpSenderUsesOwnSourceAndSelectedProfile(BatchTrafficKind kind, byte channel)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var f = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port, "HP_Template_111.xml");
        DateTimeOffset? slot = kind == BatchTrafficKind.BlockLoad
            ? DateTimeOffset.Parse("2026-09-25T09:15:00Z") : null;
        await using var session = await f.Push.OpenBatchTrafficAsync(f.Batch, kind, slot, timeout.Token);
        var sending = session.SendAsync(f.Batch.StartIndex, timeout.Token);
        using var client = await listener.AcceptTcpClientAsync(timeout.Token);
        Assert.Equal(IPAddress.IPv6Loopback, ((IPEndPoint)client.Client.RemoteEndPoint!).Address);
        using var bytes = new MemoryStream();
        await client.GetStream().CopyToAsync(bytes, timeout.Token);
        await sending;
        var decoder = new GXDLMSClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        var response = new GXReplyData();
        var notification = new GXReplyData();
        decoder.GetData(new GXByteBuffer(bytes.ToArray()), response, notification);
        var fields = Assert.IsAssignableFrom<IEnumerable>(notification.Value ?? response.Value).Cast<object>().ToArray();
        Assert.Equal(new byte[] { 0, channel, 25, 9, 0, 255 }, Assert.IsType<byte[]>(fields[1]));
        if (kind == BatchTrafficKind.BlockLoad)
        {
            byte[] rtc = Assert.IsType<byte[]>(fields[2]);
            Assert.Equal(2026, BinaryPrimitives.ReadUInt16BigEndian(rtc.AsSpan(0, 2)));
            Assert.Equal(new byte[] { 9, 25 }, rtc[2..4]);
            Assert.Equal(new byte[] { 14, 45, 0 }, rtc[5..8]);
            Assert.Equal(0, BinaryPrimitives.ReadInt16BigEndian(rtc.AsSpan(9, 2)));
        }
    }
}

public partial class MqttPushRunTests
{
    [Fact]
    public async Task ScheduledPushKeepsCompletedPayloadCountsWhenCanceled()
    {
        var f = new Fixture(1);
        f.Publisher.BeforePublish = ct => throw new ManyMeterSimulator.Networking.Push.PushCanceledException(1, 1, ct);
        await using var session = await f.Push.OpenBatchTrafficAsync(f.Batch, BatchTrafficKind.Daily, default);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => session.SendAsync(f.Batch.StartIndex, default));
        Assert.Equal(1, f.Metrics.Snapshot(0).TotalPushPayloadsSent);
        Assert.Equal(1, f.Metrics.Snapshot(0).TotalPushPayloadsFailed);
        Assert.Equal(1, f.Metrics.Snapshot(0).TotalPushMetersFailed);
    }

    [Theory]
    [InlineData(BatchTrafficKind.Instantaneous, 0)]
    [InlineData(BatchTrafficKind.BlockLoad, 5)]
    [InlineData(BatchTrafficKind.Daily, 6)]
    public async Task ScheduledMqttSenderPublishesSelectedProfile(BatchTrafficKind kind, byte channel)
    {
        var f = new Fixture(1);
        var batch = f.Batches.AddBatch("4G", "HP_Template_111.xml", 1, NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(batch.Id);
        DateTimeOffset? slot = kind == BatchTrafficKind.BlockLoad
            ? DateTimeOffset.Parse("2026-09-25T09:15:00Z") : null;
        await using (var session = await f.Push.OpenBatchTrafficAsync(batch, kind, slot, default))
            await session.SendAsync(batch.StartIndex, default);
        var message = Assert.Single(f.Publisher.Messages);
        Assert.Equal("Normal_Push/1000000002", message.Topic);
        var decoder = new GXDLMSClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        var response = new GXReplyData();
        var notification = new GXReplyData();
        decoder.GetData(new GXByteBuffer(message.Payload), response, notification);
        var fields = Assert.IsAssignableFrom<IEnumerable>(notification.Value ?? response.Value).Cast<object>().ToArray();
        Assert.Equal(new byte[] { 0, channel, 25, 9, 0, 255 }, Assert.IsType<byte[]>(fields[1]));
        if (kind == BatchTrafficKind.BlockLoad)
            Assert.Equal(new byte[] { 14, 45, 0 }, Assert.IsType<byte[]>(fields[2])[5..8]);
        Assert.Equal(0, Assert.Single(f.Publisher.PoolSettings).Qos);
        Assert.All(f.Publisher.Pools, p => Assert.True(p.Disposed));
    }

    [Fact]
    public async Task ScheduledCustomDailyUsesExistingWirepasEncoding()
    {
        var f = new Fixture(1);
        await using (var session = await f.Push.OpenBatchTrafficAsync(f.Batch, BatchTrafficKind.Daily, default))
            await session.SendAsync(f.Batch.StartIndex, default);
        Assert.Single(f.Publisher.Messages);
        Assert.All(f.Publisher.Pools, p => Assert.True(p.Disposed));
    }

    [Fact]
    public async Task ScheduledCustomBlockLoadUsesQosZero()
    {
        var f = new Fixture(1, encoder: CustomPushFixtureModel.BlockEncoder());
        var slot = DateTimeOffset.Parse("2026-09-25T09:15:00Z");
        await using (var session = await f.Push.OpenBatchTrafficAsync(f.Batch, BatchTrafficKind.BlockLoad, slot, default))
            await session.SendAsync(f.Batch.StartIndex, default);
        Assert.Single(f.Publisher.Messages);
        Assert.Equal(0, Assert.Single(f.Publisher.PoolSettings).Qos);
        Assert.All(f.Publisher.Pools, p => Assert.True(p.Disposed));
    }

    [Theory]
    [InlineData(100_000, 8)]
    [InlineData(100_001, 10)]
    [InlineData(800_000, 10)]
    public async Task ScheduledMqttPublisherCountFollowsBatchSize(int count, int publishers)
    {
        var f = new Fixture(1);
        var batch = f.Batches.AddBatch("4G", "HP_Template_111.xml", count, NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(batch.Id);
        await using (var session = await f.Push.OpenBatchTrafficAsync(batch, BatchTrafficKind.Instantaneous, default))
            await session.SendAsync(batch.StartIndex, default);
        Assert.Equal((publishers, 0), Assert.Single(f.Publisher.PoolSettings));
    }

    [Fact]
    public async Task ScheduledMqttSourceChangeStillRequiresReconnect()
    {
        var f = new Fixture(1);
        await using var session = await f.Push.OpenBatchTrafficAsync(f.Batch, BatchTrafficKind.Daily, default);
        Assert.True(f.Batches.TryStop(f.Batch.Id));
        await Assert.ThrowsAsync<BatchTrafficSourceChangedException>(() => session.SendAsync(f.Batch.StartIndex, default));
        Assert.Empty(f.Publisher.Messages);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ScheduledMqttPushBypassesSimulatedFailuresAndDelay(bool simulateOffline)
    {
        var store = new DirectionalStore();
        var badComm = new BadCommSettings(store);
        if (simulateOffline)
            Assert.True(badComm.TryUpdate(new BadCommConfig
            {
                Enabled = true,
                Auto = new AutoAllocation { NonCommPercent = 100, BadCommPercent = 0 },
            }, out _, CommunicationDirection.Push));
        var delay = new NetworkDelaySettings(Options.Create(new NetworkDelayOptions()), store);
        Assert.True(delay.TryUpdate(10_000, 10_000, CommunicationDirection.Push));
        var f = new Fixture(1, badComm: badComm, networkDelay: delay);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await using var session = await f.Push.OpenBatchTrafficAsync(f.Batch, BatchTrafficKind.Daily, default);
        await session.SendAsync(f.Batch.StartIndex, timeout.Token);
        Assert.Single(f.Publisher.Messages);
    }
}
