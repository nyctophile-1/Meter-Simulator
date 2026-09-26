using System.Collections;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using Task = System.Threading.Tasks.Task;

namespace ManyMeterSimulator.Tests;

public partial class TcpStressIntegrationTests
{
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
}
