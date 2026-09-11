using System.Collections.Concurrent;
using ManyMeterSimulator.Networking.Mqtt;

namespace ManyMeterSimulator.Tests;

public class MqttPushPoolTests
{
    [Fact]
    public async Task PoolPublishesAcrossConnections_AndKeepsEachMetersFragmentsTogether()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int count = 0;
        var connections = Enumerable.Range(0, 3).Select(_ => new TestConnection(async ct =>
        {
            if (Interlocked.Increment(ref count) == 3) entered.TrySetResult();
            await release.Task.WaitAsync(ct);
        })).ToArray();
        await using var pool = await MqttPushPool.OpenAsync(connections, 2, TimeSpan.FromSeconds(10), default);
        var sending = Enumerable.Range(0, 9).Select(i => pool.PublishMeterAsync(
            [new NicPublish($"meter/{i}", [0]), new NicPublish($"meter/{i}", [1]), new NicPublish($"meter/{i}", [2])], default)).ToArray();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.All(connections, c => Assert.Equal(1, c.Active));
        release.TrySetResult();
        var results = await Task.WhenAll(sending).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(27, results.Sum(r => r.Sent));
        Assert.All(connections, c => Assert.Equal(1, c.MaxActive));
        Assert.All(connections.SelectMany(c => c.Messages), m => Assert.Equal(2, m.Qos));
        foreach (var connection in connections)
            foreach (var meter in connection.Messages.Chunk(3))
            {
                Assert.Single(meter.Select(m => m.Message.Topic).Distinct());
                Assert.Equal(new byte[] { 0, 1, 2 }, meter.Select(m => m.Message.Payload[0]));
            }
    }

    [Fact]
    public async Task CancelInterruptsPoolWaitsAndPublishes_WithoutRetrying()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var connection = new TestConnection(async ct => { entered.TrySetResult(); await Task.Delay(Timeout.Infinite, ct); });
        await using var pool = await MqttPushPool.OpenAsync([connection], 1, TimeSpan.FromSeconds(30), default);
        using var cts = new CancellationTokenSource();
        var first = pool.PublishMeterAsync([new NicPublish("one", [0])], cts.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var waiting = pool.PublishMeterAsync([new NicPublish("two", [0])], cts.Token);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.Single(connection.Messages);
    }

    [Fact]
    public async Task TimeoutCountsTheRemainingFragmentsAsUnconfirmed()
    {
        var connection = new TestConnection(ct => Task.Delay(Timeout.Infinite, ct));
        await using var pool = await MqttPushPool.OpenAsync([connection], 2, TimeSpan.FromMilliseconds(50), default);
        var result = await pool.PublishMeterAsync([new NicPublish("one", [0]), new NicPublish("one", [1])], default);
        Assert.Equal(0, result.Sent);
        Assert.Equal(2, result.Failed);
        Assert.Contains("timed out", result.Error);
        Assert.Single(connection.Messages);
    }

    [Fact]
    public async Task FailedConnectionStartupDisposesAllPoolConnections()
    {
        var first = new TestConnection(_ => Task.CompletedTask);
        var failed = new TestConnection(_ => Task.CompletedTask) { FailConnect = true };
        await Assert.ThrowsAsync<IOException>(() => MqttPushPool.OpenAsync([first, failed], 0, TimeSpan.FromSeconds(1), default));
        Assert.True(first.Disposed);
        Assert.True(failed.Disposed);
    }

    private sealed class TestConnection(Func<CancellationToken, Task> publish) : IMqttPushConnection
    {
        public bool IsConnected { get; private set; }
        public bool Disposed { get; private set; }
        public bool FailConnect { get; init; }
        public int Active;
        public int MaxActive;
        public ConcurrentQueue<(NicPublish Message, int Qos)> Messages { get; } = new();
        public Task ConnectAsync(CancellationToken ct)
        {
            if (FailConnect) throw new IOException("Connection failed.");
            IsConnected = true;
            return Task.CompletedTask;
        }
        public async Task<bool> PublishAsync(NicPublish message, int qos, CancellationToken ct)
        {
            int active = Interlocked.Increment(ref Active);
            MaxActive = Math.Max(MaxActive, active);
            Messages.Enqueue((message, qos));
            try { await publish(ct); return true; }
            finally { Interlocked.Decrement(ref Active); }
        }
        public ValueTask DisposeAsync() { Disposed = true; IsConnected = false; return ValueTask.CompletedTask; }
    }
}
