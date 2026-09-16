using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;

namespace ManyMeterSimulator.Tests;

public partial class MqttPushRunTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StressRunsCountSendsWithoutCountingPreparation(bool prepared)
    {
        var fixture = new Fixture(3);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request);
        if (prepared) await run.PrepareAsync();
        Assert.Equal(0, fixture.Metrics.Snapshot(0).TotalPushPayloadsSent);
        if (prepared) await run.FireAsync(); else await run.SendLiveAsync();
        var snapshot = fixture.Metrics.Snapshot(NicType.MqttWirepas, 0);
        Assert.Equal(3, snapshot.TotalPushPayloadsSent);
        Assert.Equal(3, snapshot.TotalPushMetersSent);
        Assert.Equal(0, fixture.Metrics.Snapshot(NicType.Tcp4G, 0).TotalPushPayloadsSent);
    }

    [Fact]
    public async Task RegularPushDoesNotDoubleCountAndRejectsStayOutOfSuccessRate()
    {
        var fixture = new Fixture(3);
        await fixture.Push.PushBatchAsync(fixture.Batch.Id, null);
        Assert.Equal(3, fixture.Metrics.Snapshot(0).TotalPushPayloadsSent);
        fixture.Publisher.Reject = true;
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request);
        await run.SendLiveAsync();
        var snapshot = fixture.Metrics.Snapshot(0);
        Assert.Equal(3, snapshot.TotalPushPayloadsSent);
        Assert.Equal(3, snapshot.TotalPushPayloadsFailed);
        Assert.Equal(3, snapshot.TotalPushMetersFailed);
    }

    [Fact]
    public async Task LoopCountersUpdateBeforeTheLoopStops()
    {
        var fixture = new Fixture(2);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request);
        var looping = run.SendLoopAsync(new() { CyclePauseSeconds = 1 });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (fixture.Metrics.Snapshot(0).TotalPushPayloadsSent < 4)
            await Task.Delay(5, timeout.Token);
        Assert.False(looping.IsCompleted);
        run.Stop();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => looping);
        Assert.Equal(run.LoopResult!.Totals.MessagesSent, fixture.Metrics.Snapshot(0).TotalPushPayloadsSent);
    }
}

public class PushAccountingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SharedMqttBindingKeepsImgNicAttribution(bool prepared)
    {
        var metrics = new SimulatorMetrics();
        var binding = new BrokerBinding(NicType.Mqtt4G, "test");
        var pool = new Pool();
        MqttPushSource Source(int id, NicType nic) => new(id, 1, binding,
            () => [new MeterRef(id, nic)], _ => [new NicPublish("push", [1]), new NicPublish("push", [2])], () => true);
        await using var run = new MqttPushRun([Source(1, NicType.Mqtt4G), Source(2, NicType.Mqtt4GImg)],
            new Dictionary<BrokerBinding, IMqttPushPool> { [binding] = pool },
            new() { BatchIds = [1, 2], MaxConcurrency = 1 }, false, new(), _ => { }, _ => { }, metrics);
        if (prepared) { await run.PrepareAsync(); await run.FireAsync(); } else await run.SendLiveAsync();
        Assert.Equal(2, metrics.Snapshot(NicType.Mqtt4G, 0).TotalPushPayloadsSent);
        Assert.Equal(2, metrics.Snapshot(NicType.Mqtt4GImg, 0).TotalPushPayloadsSent);
        Assert.Equal(2, metrics.Snapshot(0).TotalPushMetersSent);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TcpRunCountsPartialDeliveriesAndSkippedMeters(bool prepared)
    {
        var metrics = new SimulatorMetrics();
        await using var run = new TcpPushRun([new(3,
            () => Enumerable.Range(1, 3).Select(i => new MeterRef(i, NicType.Tcp4G)),
            m => m.Index == 3 ? [] : [[1], [2]],
            (m, _, _) => Task.FromResult(m.Index == 1 ? new PushDeliveryResult(2, 0) : new(1, 1)), () => true)],
            new() { BatchIds = [1], MaxConcurrency = 1 }, false, default, _ => { }, _ => { }, metrics);
        if (prepared) { await run.PrepareAsync(); Assert.Equal(0, metrics.Snapshot(0).TotalPushMetersAttempted); await run.FireAsync(); }
        else await run.SendLiveAsync();
        var snapshot = metrics.Snapshot(0);
        Assert.Equal(3, snapshot.TotalPushPayloadsSent);
        Assert.Equal(1, snapshot.TotalPushPayloadsFailed);
        Assert.Equal(1, snapshot.TotalPushMetersSent);
        Assert.Equal(1, snapshot.TotalPushMetersFailed);
        Assert.Equal(1, snapshot.TotalPushMetersSkipped);
    }

    [Fact]
    public void RatesUseElapsedTimeAndNeverTreatLifetimeTotalsAsANewBurst()
    {
        var now = DateTimeOffset.UtcNow;
        DashboardActivitySample Sample(double seconds, long total) => new(now.AddSeconds(seconds), 0, 0, 0,
            new Dictionary<NicType, NicActivityTotals> { [NicType.Mqtt4G] = new(0, 0, total) });
        var first = Sample(0, 1_000_000);
        var last = Sample(4, 1_000_010);
        Assert.Equal(0, DashboardActivityHistory.PushesPerSecond([first], NicType.Mqtt4G));
        Assert.Equal(2.5, DashboardActivityHistory.PushesPerSecond([first, last], NicType.Mqtt4G));
        Assert.Equal(0, DashboardActivityHistory.PushesPerSecond([last, Sample(6, 1_000_010)], NicType.Mqtt4G));
        Assert.Equal(0, DashboardActivityHistory.PushesPerSecond([last, Sample(6, 0)], NicType.Mqtt4G));
    }

    private sealed class Pool : IMqttPushPool
    {
        public bool IsConnected => true;
        public Task<MqttPushDelivery> PublishMeterAsync(IReadOnlyList<NicPublish> messages, CancellationToken cancellationToken)
            => Task.FromResult(new MqttPushDelivery(messages.Count, 0));
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
