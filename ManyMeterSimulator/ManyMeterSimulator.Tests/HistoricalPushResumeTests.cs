using System.Collections.Concurrent;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;

namespace ManyMeterSimulator.Tests;

public class HistoricalPushResumeTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 20, 0, 0, 0, TimeSpan.Zero);
    private const string Ip = "0.0.25.9.0.255";
    private const string Ls = "0.5.25.9.0.255";

    private static HistoricalPushSource Source(string profile, int period, long count,
        Func<MeterRef, DateTimeOffset, CancellationToken, Task<PushDeliveryResult>> send) =>
        new(1, 1, count, NicType.Mqtt4G, profile, period, () => true, send, "Test fleet");

    private static HistoricalPushRun Run(HistoricalPushSource[] sources, int concurrency = 1,
        HistoricalPushCheckpoint? resume = null) => new(sources, [],
        new() { BatchIds = [1], MaxConcurrency = concurrency, PublisherCount = 1 },
        Start, Start.AddMinutes(30), (_, _) => Task.FromResult(true), new SimulatorMetrics(), resume);

    [Fact]
    public async Task BothProfilesWeaveAtMatchingTimesWithoutLosingDifferentCadences()
    {
        var sent = new List<(string Profile, long Meter, DateTimeOffset Time)>();
        HistoricalPushSource Create(string profile, int period) => Source(profile, period, 3, (meter, time, _) =>
        {
            sent.Add((profile, meter.Index, time));
            return Task.FromResult(new PushDeliveryResult(1, 0));
        });

        await using var run = Run([Create(Ip, 1800), Create(Ls, 900)]);
        var result = await run.SendAsync(_ => { }, default);

        Assert.Equal(15, result.Sent);
        Assert.Equal(new[] { Ip, Ls, Ip, Ls, Ip, Ls }, sent.Take(6).Select(x => x.Profile));
        Assert.Equal(new long[] { 1, 1, 2, 2, 3, 3 }, sent.Take(6).Select(x => x.Meter));
        Assert.All(sent.Skip(6).Take(3), x => Assert.Equal((Ls, Start.AddMinutes(15)), (x.Profile, x.Time)));
        Assert.Equal(sent.OrderBy(x => x.Time), sent);
        Assert.Equal(sent.Count, sent.Distinct().Count());
    }

    [Fact]
    public async Task SharedConcurrencyStartsBothProfilesBeforeEitherFleetFinishes()
    {
        var entered = new ConcurrentDictionary<string, byte>();
        var both = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var snapshot = new TaskCompletionSource<HistoricalPushProgress>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        HistoricalPushSource Create(string profile) => Source(profile, 1800, 1000, async (_, _, ct) =>
        {
            entered.TryAdd(profile, 0);
            if (entered.Count == 2)
            {
                both.TrySetResult();
            }

            await Task.Delay(Timeout.Infinite, ct);
            return new(1, 0);
        });

        await using var run = Run([Create(Ip), Create(Ls)], 2);
        var sending = run.SendAsync(p =>
        {
            if (p.CurrentSlots.Sum(s => s.InFlight) == 2)
            {
                snapshot.TrySetResult(p);
            }
        }, stop.Token);
        await both.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var live = await snapshot.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(2, live.CurrentSlots.Count);
        Assert.All(live.CurrentSlots, s => Assert.Equal(1, s.InFlight));
        Assert.Equal(0, live.Processed);

        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending);
    }

    [Fact]
    public async Task DiskCheckpointResumesCancellationHolesWithoutRepeatingSettledRecords()
    {
        string directory = Path.Combine(Path.GetTempPath(), "maya-history-test-" + Guid.NewGuid());
        var store = new JsonHistoricalPushCheckpointStore(Path.Combine(directory, "historical-push.json"));
        var sent = new ConcurrentBag<(string Profile, long Meter, DateTimeOffset Time)>();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var secondSettled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        bool resumed = false;
        HistoricalPushSource Create(string profile) => Source(profile, 1800, 3, async (meter, time, ct) =>
        {
            if (!resumed && profile == Ip && meter.Index == 1)
            {
                await secondSettled.Task.WaitAsync(ct);
                stop.Cancel();
                ct.ThrowIfCancellationRequested();
            }

            sent.Add((profile, meter.Index, time));
            if (profile == Ip && meter.Index == 2)
            {
                secondSettled.TrySetResult();
            }

            return new(1, 0);
        });

        try
        {
            await using (var first = Run([Create(Ip), Create(Ls)], 2))
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.SendAsync(_ => { }, stop.Token, store.Save));
            }

            var saved = store.Load()!;
            Assert.True(saved.HasRemaining);
            Assert.Equal(sent.Count, saved.Progress.Sent);
            Assert.Equal(0, saved.Sources[0].NextRecord);
            Assert.Contains(1L, saved.Sources[0].CompletedAhead);
            resumed = true;

            await using var continuation = Run([Create(Ip), Create(Ls)], 2, saved);
            HistoricalPushProgress? initial = null;
            var result = await continuation.SendAsync(p => initial ??= p, default, store.Save);
            Assert.Equal(saved.Progress.Sent, initial!.Sent);
            Assert.Equal(0, initial.CurrentRecordsPerSecond);
            Assert.Equal(12, result.Sent);
            Assert.Equal(12, sent.Count);
            Assert.Equal(sent.Count, sent.Distinct().Count());
            Assert.Equal(Start, result.From);
            Assert.Equal(Start.AddMinutes(30), result.To);
            Assert.False(store.Load()!.HasRemaining);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task ResumeKeepsFailuresAndSkipsAccountedAndRejectsChangedSources()
    {
        using var stop = new CancellationTokenSource();
        HistoricalPushCheckpoint? saved = null;
        int attempts = 0;
        var source = Source(Ip, 1800, 4, (_, _, _) =>
        {
            if (++attempts == 2)
            {
                stop.Cancel();
            }

            return Task.FromResult(new PushDeliveryResult(0, 1, "rejected"));
        });
        await using (var first = Run([source]))
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.SendAsync(_ => { }, stop.Token, c => saved = c));
        }

        Assert.Equal(2, saved!.Progress.Failed);
        await using (var changed = Run([source with { ResumeIdentity = "different destination" }], resume: saved))
        {
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => changed.SendAsync(_ => { }, default));
            Assert.Contains("changed", error.Message);
            Assert.Equal(2, attempts);
        }

        var remaining = source with { Send = (_, _, _) => Task.FromResult(new PushDeliveryResult(1, 0)) };
        await using var continuation = new HistoricalPushRun([remaining], [], saved.Request, Start, Start.AddMinutes(30),
            (meter, _) => Task.FromResult(meter.Index % 2 == 0), new SimulatorMetrics(), saved);
        var result = await continuation.SendAsync(_ => { }, default);
        Assert.Equal(8, result.Processed);
        Assert.Equal(2, result.Failed);
        Assert.Equal(3, result.Skipped);
        Assert.Equal(3, result.Sent);
    }

    [Fact]
    public async Task CancellationBeforeTransportCompletionRemainsPendingForContinue()
    {
        using var stop = new CancellationTokenSource();
        HistoricalPushCheckpoint? saved = null;
        var source = Source(Ip, 1800, 1, (_, _, ct) =>
        {
            stop.Cancel();
            throw new PushCanceledException(0, 1, ct);
        });
        await using (var first = Run([source]))
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.SendAsync(_ => { }, stop.Token, c => saved = c));
        }

        Assert.Equal(0, saved!.Progress.Processed);
        Assert.Equal(0, saved.Sources[0].NextRecord);
        source = source with { Send = (_, _, _) => Task.FromResult(new PushDeliveryResult(1, 0)) };
        await using var continuation = Run([source], resume: saved);
        var result = await continuation.SendAsync(_ => { }, default);
        Assert.Equal(2, result.Sent);
        Assert.Equal(0, result.Failed);
    }

    [Fact]
    public async Task CheckpointWriteFailurePreventsUnrecoverableNewRunDelivery()
    {
        int sends = 0;
        var source = Source(Ip, 1800, 1, (_, _, _) =>
        {
            sends++;
            return Task.FromResult(new PushDeliveryResult(1, 0));
        });
        await using var run = Run([source]);
        await Assert.ThrowsAsync<IOException>(() => run.SendAsync(_ => { }, default,
            _ => throw new IOException("Disk unavailable")));
        Assert.Equal(0, sends);
    }
}

public partial class MqttPushRunTests
{
    private sealed class ResumeClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 9, 20, 0, 7, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public async Task HistoricalServiceCanContinueAfterRestartUsingOriginalDatesAndLiveRate()
    {
        string directory = Path.Combine(Path.GetTempPath(), "maya-history-service-" + Guid.NewGuid());
        var store = new JsonHistoricalPushCheckpointStore(Path.Combine(directory, "historical-push.json"));
        var clock = new ResumeClock();
        var f = new Fixture(1, clock: clock);
        var batch = f.Batches.AddBatch("history", "D1_Master.xml", 2, NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(batch.Id);
        var published = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Publisher.AfterPublish = () => published.TrySetResult();

        try
        {
            await using (var first = new HistoricalPushService(f.Push, new TestLifetime(), store))
            {
                first.Start(new() { BatchIds = [batch.Id], Days = 1, RecordsPerSecond = 100, MaxConcurrency = 1, PublisherCount = 1 });
                await published.Task.WaitAsync(TimeSpan.FromSeconds(5));
                Assert.False(first.CanContinue);
                first.SetRecordsPerSecond(200);
                await first.StopAsync();
                Assert.Equal("Stopped", first.State.Phase);
                Assert.True(first.CanContinue);
            }

            var saved = store.Load()!;
            int before = f.Publisher.Messages.Count;
            Assert.Equal(before, saved.Progress.Sent);
            Assert.Equal(200, saved.Request.RecordsPerSecond);
            clock.Now = clock.Now.AddDays(2);

            await using var restarted = new HistoricalPushService(f.Push, new TestLifetime(), store);
            Assert.Equal("Paused", restarted.State.Phase);
            Assert.Equal(before, f.Publisher.Messages.Count);
            Assert.True(restarted.CanContinue);
            restarted.Continue();
            restarted.SetRecordsPerSecond(300000);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            while (restarted.State.IsActive)
            {
                await Task.Delay(10, timeout.Token);
            }

            await restarted.StopAsync();
            Assert.Equal("Completed", restarted.State.Phase);
            Assert.Equal(saved.Progress.From, restarted.State.Progress!.From);
            Assert.Equal(saved.Progress.To, restarted.State.Progress.To);
            Assert.Equal(saved.Progress.Total, restarted.State.Progress.Sent);
            Assert.Equal(saved.Progress.Total, f.Publisher.Messages.Count);
            Assert.False(restarted.CanContinue);
            Assert.All(f.Publisher.Pools, pool => Assert.True(pool.Disposed));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
