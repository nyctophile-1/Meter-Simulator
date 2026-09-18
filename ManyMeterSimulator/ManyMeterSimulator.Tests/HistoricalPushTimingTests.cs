using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Settings;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public partial class MqttPushRunTests
{
    private static NetworkDelaySettings HistoricalDelay(int milliseconds) => new(
        Options.Create(new NetworkDelayOptions()), new HistoricalPushTests.Store
        {
            Current = { NetworkDelay = new DelayRange { LowerMs = milliseconds, UpperMs = milliseconds } }
        });

    [Theory]
    [InlineData(CommClass.Healthy)]
    [InlineData(CommClass.BadComm)]
    [InlineData(CommClass.NonComm)]
    public async Task AcceleratedHistoricalReplayRetainsLossWithoutInheritingWallClockDelay(CommClass classification)
    {
        var delay = HistoricalDelay(5000);
        var f = new Fixture(1, badComm: HistoricalPushTests.Impaired(classification), networkDelay: delay);
        var batch = f.Batches.AddBatch("history", "D1_Master.xml", 2, NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(batch.Id);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var run = await f.Push.OpenHistoricalRunAsync(new()
        {
            BatchIds = [batch.Id], Days = 1, MaxConcurrency = 1, PublisherCount = 1, RecordsPerSecond = 300000
        }, timeout.Token);
        var result = await run.SendAsync(_ => { }, timeout.Token);
        Assert.Equal(result.Total, result.Processed);
        Assert.Equal(0, result.Failed);
        Assert.Equal(classification == CommClass.Healthy ? result.Total : 0, result.Sent);
        Assert.Equal(classification == CommClass.Healthy ? 0 : result.Total, result.Skipped);
        Assert.Equal(TimeSpan.Zero, f.Metrics.Snapshot(0).MaxNetworkLatency);
        Assert.Equal(5000, delay.GetCurrent(CommunicationDirection.Push).LowerMs);
        Assert.Equal(5000, delay.GetCurrent(CommunicationDirection.Pull).LowerMs);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ExplicitHistoricalDelayAndOrdinaryLivePushStillWaitAndCancel(bool historical)
    {
        var f = new Fixture(1, networkDelay: HistoricalDelay(5000));
        var batch = f.Batches.AddBatch("history", "D1_Master.xml", 1, NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(batch.Id);
        using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
        if (historical)
        {
            await using var run = await f.Push.OpenHistoricalRunAsync(new()
            {
                BatchIds = [batch.Id], SimulateNetworkDelay = true
            }, timeout.Token);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.SendAsync(_ => { }, timeout.Token));
        }
        else
        {
            await using var run = await f.Push.OpenMqttRunAsync(f.Request, timeout.Token);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.SendLiveAsync());
        }
        Assert.Empty(f.Publisher.Messages);
        Assert.All(f.Publisher.Pools, pool => Assert.True(pool.Disposed));
    }

    [Fact]
    public async Task AcceleratedReplayReadsBadCommChangesDuringTheRun()
    {
        var badComm = HistoricalPushTests.Impaired(CommClass.Healthy);
        var f = new Fixture(1, badComm: badComm, networkDelay: HistoricalDelay(5000));
        var batch = f.Batches.AddBatch("history", "D1_Master.xml", 1, NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(batch.Id);
        f.Publisher.AfterPublish = () => badComm.TryUpdate(
            HistoricalPushTests.Impaired(CommClass.NonComm).Snapshot(CommunicationDirection.Push), out _, CommunicationDirection.Push);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var run = await f.Push.OpenHistoricalRunAsync(new() { BatchIds = [batch.Id], RecordsPerSecond = 300000 }, timeout.Token);
        var result = await run.SendAsync(_ => { }, timeout.Token);
        Assert.Equal(1, result.Sent);
        Assert.Equal(result.Total - 1, result.Skipped);
        Assert.Equal(0, result.Failed);
    }
}
