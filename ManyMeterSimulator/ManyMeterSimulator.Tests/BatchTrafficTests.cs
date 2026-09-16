using System.Collections.Concurrent;
using System.Text.Json;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public class BatchTrafficTests
{
    private static readonly TimeZoneInfo India = TimeZoneInfo.FindSystemTimeZoneById("Asia/Kolkata");

    [Fact]
    public void SettingsRoundTripWithoutChangingAllocationOrBatchStatus()
    {
        var store = new MemoryStore();
        var registry = new MeterRegistry(store);
        var batch = registry.AddBatch("batch", "template", 12);
        registry.TryStart(batch.Id);
        foreach (var kind in Enum.GetValues<BatchTrafficKind>()) registry.SetTraffic(batch.Id, kind, kind != BatchTrafficKind.Routing);
        var before = registry.Snapshot();
        var restored = new MeterRegistry(store).Snapshot();
        Assert.Equal(JsonSerializer.Serialize(before), JsonSerializer.Serialize(restored));
        Assert.False(restored.Batches[0].Traffic.Routing);
        Assert.True(restored.Batches[0].Traffic.Daily);
        var imported = new MeterRegistry();
        imported.ImportSnapshot(restored);
        Assert.Equal(restored.Batches[0].Traffic, imported.Batches.Single().Traffic);
        var legacy = JsonSerializer.Deserialize<PersistedBatch>("{\"Id\":1}")!;
        Assert.True(legacy.Traffic.Routing);
        Assert.False(legacy.Traffic.Instantaneous);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(100_000)]
    [InlineData(1_000_000)]
    public void DistributionCoversEveryMeterExactlyOnceWithEvenOneSecondBuckets(long count)
    {
        long total = 0, min = long.MaxValue, max = 0;
        for (int second = 0; second < 1800; second++)
        {
            long size = BatchTrafficSchedule.FirstMeter(count, second + 1) - BatchTrafficSchedule.FirstMeter(count, second);
            total += size;
            min = Math.Min(min, size);
            max = Math.Max(max, size);
        }
        Assert.Equal(count, total);
        Assert.InRange(max - min, 0, 1);
    }

    [Theory]
    [InlineData("2026-09-13T18:29:59Z", "2026-09-13T18:30:00Z")]
    [InlineData("2026-09-13T18:30:00Z", "2026-09-13T18:30:00Z")]
    [InlineData("2026-09-13T18:59:59Z", "2026-09-13T18:30:00Z")]
    [InlineData("2026-09-13T19:00:00Z", "2026-09-14T18:30:00Z")]
    public void DailyWindowUsesIndiaMidnightAndClosesAtHalfPast(string at, string expected)
    {
        var window = BatchTrafficSchedule.Window(DateTimeOffset.Parse(at), BatchTrafficKind.Daily, India);
        Assert.Equal(DateTimeOffset.Parse(expected), window.Start);
        Assert.Equal(TimeSpan.FromMinutes(30), window.End - window.Start);
    }

    [Theory]
    [InlineData(BatchTrafficKind.Routing)]
    [InlineData(BatchTrafficKind.Instantaneous)]
    [InlineData(BatchTrafficKind.BlockLoad)]
    public async Task EachStreamSendsOnePassSpreadAcrossWindowAndRepeats(BatchTrafficKind kind)
    {
        var f = new Fixture("2026-09-13T18:30:00Z", 3, kind);
        await f.Service.StartAsync(default);
        try
        {
            await Until(() => f.Sender.Sent.Count == 1 && f.Clock.ActiveTimers == 3);
            f.Clock.Advance(TimeSpan.FromMinutes(10));
            await Until(() => f.Sender.Sent.Count == 2 && f.Clock.ActiveTimers == 3);
            f.Clock.Advance(TimeSpan.FromMinutes(10));
            await Until(() => f.Sender.Sent.Count == 3 && f.Clock.ActiveTimers == 3);
            Assert.Equal(new long[] { 1, 2, 3 }, f.Sender.Sent.ToArray());
            f.Clock.Advance(TimeSpan.FromMinutes(10));
            await Until(() => f.Sender.Sent.Count == 4);
        }
        finally
        {
            await f.Service.StopAsync(default);
            f.Service.Dispose();
        }
    }

    [Fact]
    public async Task DailyWaitsForMidnightAndDoesNotRepeatAtHalfPast()
    {
        var f = new Fixture("2026-09-13T18:29:00Z", 1, BatchTrafficKind.Daily);
        await f.Service.StartAsync(default);
        await Until(() => f.Service.State(f.Batch, BatchTrafficKind.Daily).Status == "Scheduled");
        Assert.Empty(f.Sender.Sent);
        f.Clock.Advance(TimeSpan.FromMinutes(1));
        await Until(() => f.Sender.Sent.Count == 1);
        f.Clock.Advance(TimeSpan.FromMinutes(30));
        await Until(() => f.Service.State(f.Batch, BatchTrafficKind.Daily).NextWindow == DateTimeOffset.Parse("2026-09-14T18:30:00Z"));
        Assert.Single(f.Sender.Sent);
        await f.Service.StopAsync(default);
        f.Service.Dispose();
    }

    [Theory]
    [InlineData(BatchTrafficKind.Routing)]
    [InlineData(BatchTrafficKind.Instantaneous)]
    [InlineData(BatchTrafficKind.BlockLoad)]
    [InlineData(BatchTrafficKind.Daily)]
    public async Task StopCancelsInFlightTrafficWithoutStoppingMeterBatch(BatchTrafficKind kind)
    {
        var f = new Fixture("2026-09-13T18:30:00Z", 1, kind);
        f.Sender.Block = true;
        await f.Service.StartAsync(default);
        await Until(() => f.Sender.Entered);
        f.Registry.SetTraffic(f.Batch.Id, kind, false);
        await Until(() => f.Sender.Canceled);
        Assert.Equal(BatchStatus.Running, f.Batch.Status);
        Assert.Equal("Stopped", f.Service.State(f.Batch, kind).Status);
        await f.Service.StopAsync(default);
        f.Service.Dispose();
    }

    [Fact]
    public async Task DailyDeadlineCancelsInFlightSendAtHalfPast()
    {
        var f = new Fixture("2026-09-13T18:30:00Z", 1, BatchTrafficKind.Daily);
        f.Sender.Block = true;
        await f.Service.StartAsync(default);
        await Until(() => f.Sender.Entered);
        f.Clock.Advance(TimeSpan.FromMinutes(30));
        await Until(() => f.Sender.Canceled);
        Assert.Empty(f.Sender.Sent);
        await f.Service.StopAsync(default);
        f.Service.Dispose();
    }

    [Fact]
    public async Task StoppingBatchCancelsTrafficAndKeepsItsSavedSwitch()
    {
        var f = new Fixture("2026-09-13T18:30:00Z", 1, BatchTrafficKind.Routing);
        f.Sender.Block = true;
        await f.Service.StartAsync(default);
        await Until(() => f.Sender.Entered);
        f.Registry.TryStop(f.Batch.Id);
        await Until(() => f.Sender.Canceled);
        Assert.True(f.Batch.Traffic.Routing);
        Assert.Equal("Waiting for batch", f.Service.State(f.Batch, BatchTrafficKind.Routing).Status);
        await f.Service.StopAsync(default);
        f.Service.Dispose();
    }

    [Fact]
    public async Task StartingMidWindowSkipsPastSlotsInsteadOfBursting()
    {
        var f = new Fixture("2026-09-13T18:45:00Z", 1800, BatchTrafficKind.Routing);
        await f.Service.StartAsync(default);
        await Until(() => f.Sender.Sent.Count == 1);
        Assert.Equal(901, f.Sender.Sent.Single());
        await f.Service.StopAsync(default);
        f.Service.Dispose();
    }

    private static async Task Until(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!condition()) await Task.Delay(5, timeout.Token);
    }

    private sealed class Fixture
    {
        public MeterRegistry Registry { get; } = new();
        public MeterBatch Batch { get; }
        public Clock Clock { get; }
        public Sender Sender { get; } = new();
        public BatchTrafficService Service { get; }
        public Fixture(string at, int count, BatchTrafficKind kind)
        {
            Clock = new Clock(DateTimeOffset.Parse(at));
            Batch = Registry.AddBatch("batch", "template", count);
            Registry.SetTraffic(Batch.Id, BatchTrafficKind.Routing, false);
            Registry.SetTraffic(Batch.Id, kind, true);
            Registry.TryStart(Batch.Id);
            Service = new(Registry, Sender, Clock, Options.Create(new BatchTrafficOptions()), NullLogger<BatchTrafficService>.Instance);
        }
    }

    private sealed class Sender : IBatchTrafficSender
    {
        public ConcurrentQueue<long> Sent { get; } = new();
        public bool Block, Entered, Canceled;
        public Task<IBatchTrafficSession> OpenAsync(MeterBatch batch, BatchTrafficKind kind, CancellationToken token) =>
            Task.FromResult<IBatchTrafficSession>(new BatchTrafficSession(async (index, ct) =>
            {
                Entered = true;
                try { if (Block) await Task.Delay(Timeout.Infinite, ct); }
                catch (OperationCanceledException) { Canceled = true; throw; }
                Sent.Enqueue(index);
            }, () => ValueTask.CompletedTask));
    }

    private sealed class MemoryStore : IBatchStore
    {
        private string _json = "{}";
        public BatchStoreSnapshot Load() => JsonSerializer.Deserialize<BatchStoreSnapshot>(_json)!;
        public void Save(BatchStoreSnapshot snapshot) => _json = JsonSerializer.Serialize(snapshot);
    }

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        private readonly object _gate = new();
        private readonly List<Timer> _timers = [];
        public int ActiveTimers { get { lock (_gate) return _timers.Count(t => t.At != DateTimeOffset.MaxValue); } }
        public override DateTimeOffset GetUtcNow() { lock (_gate) return now; }
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new Timer(this, callback, state);
            lock (_gate) _timers.Add(timer);
            timer.Change(dueTime, period);
            return timer;
        }
        public void Advance(TimeSpan elapsed)
        {
            List<Timer> due;
            lock (_gate)
            {
                now += elapsed;
                due = _timers.Where(t => t.At <= now).ToList();
                foreach (var timer in due) timer.At = timer.Period > TimeSpan.Zero ? now + timer.Period : DateTimeOffset.MaxValue;
            }
            foreach (var timer in due) timer.Fire();
        }
        private sealed class Timer(Clock clock, TimerCallback callback, object? state) : ITimer
        {
            public DateTimeOffset At = DateTimeOffset.MaxValue;
            public TimeSpan Period;
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                lock (clock._gate) { At = dueTime < TimeSpan.Zero ? DateTimeOffset.MaxValue : clock.GetUtcNow() + dueTime; Period = period; }
                return true;
            }
            public void Fire() => callback(state);
            public void Dispose() { lock (clock._gate) { At = DateTimeOffset.MaxValue; clock._timers.Remove(this); } }
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
