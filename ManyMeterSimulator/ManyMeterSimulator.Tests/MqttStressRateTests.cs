using ManyMeterSimulator.Testing;

namespace ManyMeterSimulator.Tests;

public partial class MqttPushRunTests
{
    [Fact]
    public async Task ServiceRateChangesReachExistingPublishersAndSharedState()
    {
        var fixture = new Fixture(1);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Publisher.BeforePublish = async ct =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.Infinite, ct);
        };
        await using var service = new MqttStressService(fixture.Push, new TestLifetime());
        service.Start(fixture.Request, false, new());
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(100, service.State.Request!.PublishesPerSecond);
        var limiter = Assert.Single(fixture.Publisher.Pools).RateLimiter!;
        service.SetPublishRate(300_000);
        Assert.Equal(300_000, limiter.Rate);
        Assert.Equal(300_000, service.State.Request.PublishesPerSecond);
        service.SetPublishRate(100);
        Assert.Equal(100, limiter.Rate);
        Assert.Throws<ArgumentOutOfRangeException>(() => service.SetPublishRate(99));
        Assert.Equal(100, service.State.Request.PublishesPerSecond);
        Assert.Single(fixture.Publisher.Pools);
        await service.StopAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("Stopped", service.State.Phase);
        Assert.Throws<InvalidOperationException>(() => service.SetPublishRate(1000));
    }
}
