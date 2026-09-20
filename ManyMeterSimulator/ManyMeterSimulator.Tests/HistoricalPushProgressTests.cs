using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;

namespace ManyMeterSimulator.Tests;

public class HistoricalPushProgressTests
{
    private static readonly DateTimeOffset Reading = new(2026, 9, 15, 18, 30, 0, TimeSpan.Zero);

    private static HistoricalPushSource Source(string profile = "0.0.25.9.0.255", int batch = 7,
        Func<MeterRef, DateTimeOffset, CancellationToken, Task<PushDeliveryResult>>? send = null) =>
        new(batch, 1, 10, NicType.Mqtt4G, profile, 900, () => true,
            send ?? ((_, _, _) => Task.FromResult(new PushDeliveryResult(1, 0))), $"Fleet {batch}");

    [Fact]
    public void MeasuredRatesUseCompletionsAndDecayToZeroWhenDeliveryStalls()
    {
        var source = Source();
        var tracker = new HistoricalPushTelemetry([source], Reading, Reading);
        tracker.BeginSlot(source, Reading);
        tracker.Sending(1);
        Assert.Equal(0, tracker.Snapshot(TimeSpan.Zero).Sent);

        tracker.Record(source, Reading, sent: 4, messages: 8);
        tracker.Record(source, Reading, skipped: 3, failed: 2, rejected: 2);
        var active = tracker.Snapshot(TimeSpan.FromSeconds(1));
        Assert.Equal(4, active.CurrentRecordsPerSecond);
        Assert.Equal(8, active.CurrentMessagesPerSecond);
        Assert.Equal(9, active.Processed);
        Assert.Equal(1, active.CurrentSlot!.InFlight);

        var stalled = tracker.Snapshot(TimeSpan.FromSeconds(6));
        Assert.Equal(0, stalled.CurrentRecordsPerSecond);
        Assert.Equal(0, stalled.CurrentMessagesPerSecond);
        Assert.Equal(4.0 / 6, stalled.RecordsPerSecond);
        Assert.Equal(5, stalled.RateWindowSeconds);

        var finished = tracker.Snapshot(TimeSpan.FromSeconds(6), finished: true);
        Assert.Null(finished.CurrentSlot);
        Assert.Equal(0, finished.CurrentRecordsPerSecond);
        Assert.Equal(4, finished.Sent);
        Assert.Equal(Reading, finished.LastSuccessfulPush!.ReadingTime);
    }

    [Fact]
    public void ProfileAndBatchCountersStaySeparateAndOnlySuccessfulReadingsMoveTheirDates()
    {
        var ip = Source();
        var block = Source("0.5.25.9.0.255", 8);
        var tracker = new HistoricalPushTelemetry([ip, block], Reading, Reading.AddMinutes(15));
        tracker.BeginSlot(ip, Reading);
        tracker.Record(ip, Reading, sent: 1, messages: 2);
        var earlier = tracker.Snapshot(TimeSpan.FromSeconds(1));
        tracker.BeginSlot(block, Reading);
        tracker.Record(block, Reading, failed: 1, messages: 1, rejected: 1);
        tracker.BeginSlot(ip, Reading.AddMinutes(15));
        tracker.Record(ip, Reading.AddMinutes(15), skipped: 10);
        var snapshot = tracker.Snapshot(TimeSpan.FromSeconds(2));

        Assert.Equal(7, snapshot.CurrentSlot!.Position.BatchId);
        Assert.Equal("Instantaneous", snapshot.CurrentSlot.Position.ProfileName);
        Assert.Equal(Reading.AddMinutes(15), snapshot.CurrentSlot.Position.ReadingTime);
        Assert.Equal(10, snapshot.CurrentSlot.Skipped);
        Assert.Equal(0, snapshot.CurrentSlot.Sent);
        Assert.Equal(Reading, snapshot.LastSuccessfulPush!.ReadingTime);
        Assert.Equal(40, snapshot.Total);
        Assert.Equal(1, snapshot.Profiles[0].Sent);
        Assert.Equal(Reading, snapshot.Profiles[0].LastSentReading);
        Assert.Null(snapshot.Profiles[1].FirstSentReading);
        Assert.Equal("Block load", snapshot.Profiles[1].ProfileName);
        Assert.Equal(1, snapshot.Profiles[1].MessagesSent);
        Assert.Equal(0, earlier.Profiles[0].Skipped);
    }

    [Fact]
    public async Task LiveSnapshotShowsTheBlockedSendAndCancellationDoesNotInventSuccess()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var live = new TaskCompletionSource<HistoricalPushProgress>(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = Source(send: async (_, _, ct) =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.Infinite, ct);
            return new(1, 0);
        });
        await using var run = new HistoricalPushRun([source], [], new() { MaxConcurrency = 1 },
            Reading, Reading, (_, _) => Task.FromResult(true), new SimulatorMetrics());
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        HistoricalPushProgress? final = null;
        var sending = run.SendAsync(p =>
        {
            final = p;
            if (p.CurrentSlot?.InFlight == 1)
            {
                live.TrySetResult(p);
            }
        }, stop.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var progress = await live.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("Fleet 7", progress.CurrentSlot!.Position.BatchName);
        Assert.Equal(Reading, progress.CurrentSlot.Position.ReadingTime);
        Assert.Equal(0, progress.Sent);
        Assert.Equal(0, progress.CurrentMessagesPerSecond);
        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending);
        Assert.Null(final!.CurrentSlot);
        Assert.Equal(0, final.Sent);
        Assert.Null(final.LastSuccessfulPush);
    }

    [Fact]
    public async Task PartialCancellationRetainsOnlyConfirmedPayloadCounts()
    {
        using var stop = new CancellationTokenSource();
        var source = Source(send: (_, _, ct) =>
        {
            stop.Cancel();
            throw new PushCanceledException(2, 1, ct);
        });
        await using var run = new HistoricalPushRun([source], [], new() { MaxConcurrency = 1 },
            Reading, Reading, (_, _) => Task.FromResult(true), new SimulatorMetrics());
        HistoricalPushProgress? final = null;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.SendAsync(p => final = p, stop.Token));
        Assert.Equal(0, final!.Sent);
        Assert.Equal(1, final.Failed);
        Assert.Equal(2, final.MessagesSent);
        Assert.Equal(1, final.MessagesFailed);
        Assert.Equal(2, Assert.Single(final.Profiles).MessagesSent);
        Assert.Null(final.LastSuccessfulPush);
        Assert.Null(final.CurrentSlot);
    }

    [Fact]
    public async Task ParallelDeliveryAndProfileTransitionsPreserveExactTotals()
    {
        var sources = new[] { Source() with { Count = 2000 }, Source("0.5.25.9.0.255", 8) with { Count = 2000 } };
        await using var run = new HistoricalPushRun(sources, [], new() { MaxConcurrency = 128 },
            Reading, Reading.AddMinutes(15), (meter, _) => Task.FromResult(meter.Index % 2 == 0), new SimulatorMetrics());
        var result = await run.SendAsync(_ => { }, default);
        Assert.Equal(8000, result.Total);
        Assert.Equal(4000, result.Sent);
        Assert.Equal(4000, result.Skipped);
        Assert.Equal(result.Sent, result.Profiles.Sum(p => p.Sent));
        Assert.Equal(result.MessagesSent, result.Profiles.Sum(p => p.MessagesSent));
        Assert.All(result.Profiles, p => Assert.Equal(Reading.AddMinutes(15), p.LastSentReading));
        Assert.Null(result.CurrentSlot);
        Assert.Equal(0, result.CurrentRecordsPerSecond);
    }
}
