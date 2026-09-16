using System.Collections.Concurrent;
using System.Diagnostics;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Tests;

public class MqttPublishRateLimiterTests
{
    [Theory]
    [InlineData(100)]
    [InlineData(1_000)]
    [InlineData(300_000)]
    public void BudgetMatchesOneSecondAndDoesNotAccumulateAfterIdle(int rate)
    {
        var clock = new ManualClock();
        var limiter = new MqttPublishRateLimiter(rate, clock);
        Assert.False(limiter.TryAcquire(out _));
        int sent = 0;
        for (int i = 0; i < 100; i++)
        {
            clock.Advance(TimeSpan.FromMilliseconds(10));
            while (limiter.TryAcquire(out _)) sent++;
        }
        Assert.Equal(rate, sent);
        clock.Advance(TimeSpan.FromHours(1));
        int burst = 0;
        while (limiter.TryAcquire(out _)) burst++;
        Assert.Equal(rate / 100, burst);
    }

    [Fact]
    public void ReducingRateDiscardsOldCreditAndIncreasingUsesNewRateImmediately()
    {
        var clock = new ManualClock();
        var limiter = new MqttPublishRateLimiter(300_000, clock);
        clock.Advance(TimeSpan.FromMilliseconds(10));
        Assert.True(limiter.TryAcquire(out _));
        limiter.SetRate(100);
        Assert.False(limiter.TryAcquire(out _));
        clock.Advance(TimeSpan.FromMilliseconds(9));
        Assert.False(limiter.TryAcquire(out _));
        clock.Advance(TimeSpan.FromMilliseconds(1));
        Assert.True(limiter.TryAcquire(out _));
        Assert.False(limiter.TryAcquire(out _));
        limiter.SetRate(300_000);
        clock.Advance(TimeSpan.FromMilliseconds(1));
        int sent = 0;
        while (limiter.TryAcquire(out _)) sent++;
        Assert.Equal(300, sent);
    }

    [Fact]
    public void ConcurrentPublishersCannotMultiplyTheBudget()
    {
        var clock = new ManualClock();
        var limiter = new MqttPublishRateLimiter(300_000, clock);
        clock.Advance(TimeSpan.FromMilliseconds(10));
        int sent = 0;
        Parallel.For(0, 256, worker =>
        {
            while (limiter.TryAcquire(out _)) Interlocked.Increment(ref sent);
        });
        Assert.Equal(3000, sent);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(99)]
    [InlineData(300001)]
    public void RejectsInvalidRates(int rate) => Assert.Throws<ArgumentOutOfRangeException>(() => new MqttPublishRateLimiter(rate));

    [Fact]
    public async Task CancellationInterruptsWaitingForCredit()
    {
        var limiter = new MqttPublishRateLimiter(100, new ManualClock());
        using var stop = new CancellationTokenSource();
        var waiting = limiter.WaitAsync(stop.Token).AsTask();
        Assert.False(waiting.IsCompleted);
        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting.WaitAsync(TimeSpan.FromSeconds(1)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LiveAndPreparedRunsShareMessageBudgetAcrossBrokersAndFragments(bool prepared)
    {
        var sent = new ConcurrentQueue<long>();
        var bindings = new[] { new BrokerBinding(NicType.Mqtt4G, "a"), new BrokerBinding(NicType.Mqtt4G, "b") };
        var pools = new Dictionary<BrokerBinding, IMqttPushPool>();
        foreach (var binding in bindings)
            pools.Add(binding, await MqttPushPool.OpenAsync([new RecordingConnection(sent)], 0, TimeSpan.FromSeconds(1), default));
        var sources = bindings.Select((b, i) => new MqttPushSource(i + 1, 1, b,
            () => [new(i + 1, NicType.Mqtt4G)],
            _ => Enumerable.Range(0, 25).Select(n => new NicPublish($"meter/{i}", [(byte)n])).ToArray(), () => true)).ToArray();
        await using var run = new MqttPushRun(sources, pools,
            new() { BatchIds = [1, 2], PublisherCount = 1, MaxConcurrency = 2, PublishesPerSecond = 100 },
            false, new CancellationTokenSource(), _ => { }, _ => { });
        if (prepared) { await run.PrepareAsync(); Assert.Empty(sent); }
        var result = await (prepared ? run.FireAsync() : run.SendLiveAsync()).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(50, result.MessagesSent);
        Assert.Equal(2, result.MetersSent);
        var times = sent.Order().ToArray();
        Assert.Equal(50, times.Length);
        Assert.True(Stopwatch.GetElapsedTime(times[0], times[^1]) >= TimeSpan.FromMilliseconds(480));
    }

    [Fact]
    public async Task RunningPoolAppliesRateReductionBetweenFragments()
    {
        var sent = new ConcurrentQueue<long>();
        var limiter = new MqttPublishRateLimiter(300_000);
        var connection = new RecordingConnection(sent)
        {
            AfterPublish = () =>
            {
                if (sent.Count == 5) limiter.SetRate(100);
                if (sent.Count == 30) limiter.SetRate(300_000);
            },
        };
        await using var pool = await MqttPushPool.OpenAsync([connection], 0, TimeSpan.FromSeconds(1), default);
        var messages = Enumerable.Range(0, 50).Select(n => new NicPublish("meter", [(byte)n])).ToArray();
        var result = await pool.PublishMeterAsync(messages, default, limiter).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(50, result.Sent);
        Assert.Equal(0, result.Failed);
        var times = sent.ToArray();
        Assert.True(Stopwatch.GetElapsedTime(times[4], times[29]) >= TimeSpan.FromMilliseconds(240));
        Assert.Equal(300_000, limiter.Rate);
    }

    private sealed class ManualClock : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        public void Advance(TimeSpan time) => _ticks += time.Ticks;
    }

    private sealed class RecordingConnection(ConcurrentQueue<long> sent) : IMqttPushConnection
    {
        public Action? AfterPublish { get; init; }
        public bool IsConnected => true;
        public Task ConnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<bool> PublishAsync(NicPublish message, int qos, CancellationToken cancellationToken)
        {
            sent.Enqueue(Stopwatch.GetTimestamp());
            AfterPublish?.Invoke();
            return Task.FromResult(true);
        }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
