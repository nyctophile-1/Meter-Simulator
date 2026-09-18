using System.Diagnostics;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;

namespace ManyMeterSimulator.Tests;

public class HistoricalPushRateTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(300000)]
    public async Task ActiveRunCanReduceIncreaseAndRemoveItsRateLimit(int initialRate)
    {
        var time = DateTimeOffset.UnixEpoch;
        var sentAt = new List<long>();
        HistoricalPushRun run = null!;
        var source = new HistoricalPushSource(1, 1, 100, NicType.Mqtt4G, "test", 900, () => true,
            (_, _, _) =>
            {
                sentAt.Add(Stopwatch.GetTimestamp());
                if (sentAt.Count == 5) run.SetRecordsPerSecond(100);
                if (sentAt.Count == 30) run.SetRecordsPerSecond(300000);
                if (sentAt.Count == 50) run.SetRecordsPerSecond(0);
                return Task.FromResult(new PushDeliveryResult(1, 0));
            });
        await using (run = new HistoricalPushRun([source], [], new()
        {
            BatchIds = [1], MaxConcurrency = 1, PublisherCount = 1, RecordsPerSecond = initialRate
        }, time, time, (_, _) => Task.FromResult(true), new SimulatorMetrics()))
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var result = await run.SendAsync(_ => { }, timeout.Token);
            Assert.Equal(100, result.Sent);
            Assert.Equal(0, result.Skipped);
            Assert.Equal(0, run.RecordsPerSecond);
            Assert.True(Stopwatch.GetElapsedTime(sentAt[4], sentAt[29]) >= TimeSpan.FromMilliseconds(240));
        }
    }

    [Fact]
    public async Task RemovingLimitReleasesWorkersAlreadyWaitingForBudget()
    {
        var time = DateTimeOffset.UnixEpoch;
        var source = new HistoricalPushSource(1, 1, 1000, NicType.Tcp4G, "test", 900, () => true,
            (_, _, _) => Task.FromResult(new PushDeliveryResult(1, 0)));
        await using var run = new HistoricalPushRun([source], [], new()
        {
            BatchIds = [1], MaxConcurrency = 1024, RecordsPerSecond = 100
        }, time, time, (_, _) => Task.FromResult(true), new SimulatorMetrics());
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var sending = run.SendAsync(_ => { }, timeout.Token);
        await Task.Delay(50, timeout.Token);
        Assert.False(sending.IsCompleted);
        run.SetRecordsPerSecond(0);
        var result = await sending.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(1000, result.Sent);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(100)]
    [InlineData(300000)]
    public void AcceptsUnthrottledOrExplicitRate(int rate) =>
        new HistoricalPushRequest { BatchIds = [1], RecordsPerSecond = rate }.Validate();

    [Theory]
    [InlineData(-1)]
    [InlineData(99)]
    [InlineData(300001)]
    public void RejectsInvalidRate(int rate) => Assert.Throws<ArgumentOutOfRangeException>(() =>
        new HistoricalPushRequest { BatchIds = [1], RecordsPerSecond = rate }.Validate());

    [Fact]
    public async Task DefaultRunHasNoTimedCeilingAndStillCountsGaps()
    {
        var time = DateTimeOffset.UnixEpoch;
        var source = new HistoricalPushSource(1, 1, 10000, NicType.Mqtt4G, "test", 900, () => true,
            (_, _, _) => Task.FromResult(new PushDeliveryResult(1, 0)));
        var request = new HistoricalPushRequest { BatchIds = [1] };
        request.Validate();
        await using var run = new HistoricalPushRun([source], [], request, time, time,
            (meter, _) => Task.FromResult(meter.Index % 2 == 0), new SimulatorMetrics());
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var result = await run.SendAsync(_ => { }, timeout.Token);
        Assert.Equal(10000, result.Processed);
        Assert.Equal(5000, result.Sent);
        Assert.Equal(5000, result.Skipped);
        Assert.Equal(0, result.Failed);
    }

    [Fact]
    public async Task OptionalRateBudgetIncludesSkippedRecords()
    {
        var time = DateTimeOffset.UnixEpoch;
        var source = new HistoricalPushSource(1, 1, 100, NicType.Mqtt4G, "test", 900, () => true,
            (_, _, _) => throw new InvalidOperationException("All records should be skipped."));
        await using var run = new HistoricalPushRun([source], [], new() { BatchIds = [1], RecordsPerSecond = 100 },
            time, time, (_, _) => Task.FromResult(false), new SimulatorMetrics());
        var watch = Stopwatch.StartNew();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var result = await run.SendAsync(_ => { }, timeout.Token);
        Assert.Equal(100, result.Skipped);
        Assert.Equal(0, result.Failed);
        Assert.True(watch.Elapsed >= TimeSpan.FromMilliseconds(900));
    }
}
