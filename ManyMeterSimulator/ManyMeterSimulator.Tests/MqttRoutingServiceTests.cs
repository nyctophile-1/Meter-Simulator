using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Logging.Abstractions;

namespace ManyMeterSimulator.Tests;

public sealed class MqttRoutingServiceTests
{
    [Fact]
    public async Task PublishesEveryActiveNodeOnceOnItsBoundBrokerPerCycle()
    {
        var fixture = new Fixture();
        fixture.Add(NicType.Mqtt4G, "a", 3);
        fixture.Add(NicType.Mqtt4GImg, "b", 2);
        fixture.Add(NicType.Tcp4G, "a");
        fixture.Add(NicType.MqttWirepas, "b");
        fixture.Add(NicType.MqttKmesh, "b");
        await fixture.Service.PublishRoutingAsync(default);

        Assert.Equal(8, fixture.Publisher.Messages.Count);
        Assert.Equal(8, fixture.Publisher.Messages.Select(m => m.Message.Topic).Distinct().Count());
        Assert.All(fixture.Publisher.Messages, m => Assert.Empty(m.Message.Payload));
        Assert.Equal(new[] { "FakeRouting/1000000001/3", "FakeRouting/1000000002/3", "FakeRouting/1000000003/3", "FakeRouting/1000000006/4" },
            fixture.Publisher.Messages.Where(m => m.BrokerKey == "a").Select(m => m.Message.Topic));
        Assert.Equal(new[] { "FakeRouting/1000000004/3", "FakeRouting/1000000005/3", "FakeRouting/1000000007/2", "FakeRouting/1000000008/1" },
            fixture.Publisher.Messages.Where(m => m.BrokerKey == "b").Select(m => m.Message.Topic));
        Assert.All(fixture.Publisher.Pools, p => Assert.True(p.Disposed));

        await fixture.Service.PublishRoutingAsync(default);
        Assert.Equal(16, fixture.Publisher.Messages.Count);
    }

    [Fact]
    public async Task SkipsInactiveUnboundMissingAndDisabledBatches()
    {
        var f = new Fixture();
        foreach (var status in new[] { BatchStatus.NotStarted, BatchStatus.Starting, BatchStatus.Stopped })
            f.Add(NicType.Mqtt4G, "a").Status = status;
        f.Add(NicType.Mqtt4G, null);
        f.Add(NicType.Mqtt4G, "missing");
        f.Network.AddBroker(new BrokerEndpoint { Key = "disabled", Host = "localhost", Enabled = false }, false);
        f.Add(NicType.Mqtt4G, "disabled");
        await f.Service.PublishRoutingAsync(default);
        Assert.Empty(f.Publisher.Messages);
        Assert.Empty(f.Publisher.Pools);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StopsBatchWhenStoppedOrReboundDuringCycle(bool rebind)
    {
        var f = new Fixture();
        var batch = f.Add(NicType.Mqtt4G, "a", 3);
        f.Publisher.AfterPublish = () =>
        {
            if (rebind) f.Registry.SetNetworkBinding(batch.Id, "b", null);
            else f.Registry.TryStop(batch.Id);
        };
        await f.Service.PublishRoutingAsync(default);
        Assert.Single(f.Publisher.Messages);
        Assert.True(f.Publisher.Pools.Single().Disposed);
    }

    [Fact]
    public async Task FailedBrokerDoesNotBlockOtherBatchesOrReplayMessages()
    {
        var f = new Fixture();
        f.Add(NicType.Mqtt4G, "a", 3);
        f.Add(NicType.Mqtt4G, "b", 2);
        f.Publisher.FailBroker = "a";
        await f.Service.PublishRoutingAsync(default);
        Assert.Single(f.Publisher.Messages, m => m.BrokerKey == "a");
        Assert.Equal(2, f.Publisher.Messages.Count(m => m.BrokerKey == "b"));
        Assert.All(f.Publisher.Pools, p => Assert.True(p.Disposed));
    }

    [Fact]
    public async Task CancellationStopsPublishingAndDisposesPool()
    {
        var f = new Fixture();
        f.Add(NicType.Mqtt4G, "a", 3);
        using var stop = new CancellationTokenSource();
        f.Publisher.AfterPublish = stop.Cancel;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Service.PublishRoutingAsync(stop.Token));
        Assert.Single(f.Publisher.Messages);
        Assert.True(f.Publisher.Pools.Single().Disposed);
    }

    private sealed class Fixture
    {
        public MeterRegistry Registry { get; } = new();
        public NetworkRegistry Network { get; } = new();
        public Publisher Publisher { get; } = new();
        public MqttRoutingService Service { get; }

        public Fixture()
        {
            foreach (var key in new[] { "a", "b" })
                Network.AddBroker(new BrokerEndpoint { Key = key, Host = "localhost" }, false);
            Service = new(Registry, Network, Publisher, NullLogger<MqttRoutingService>.Instance);
        }

        public MeterBatch Add(NicType nic, string? broker, int count = 1)
        {
            var batch = Registry.AddBatch("routing", "test.xml", count, nic, null, broker);
            Registry.TryStart(batch.Id);
            return batch;
        }
    }

    private sealed class Publisher : IMqttRoutingPublisher
    {
        public List<(string BrokerKey, NicPublish Message)> Messages { get; } = [];
        public List<Pool> Pools { get; } = [];
        public string? FailBroker { get; set; }
        public Action? AfterPublish { get; set; }
        public Task<IMqttPushPool> OpenPoolAsync(BrokerEndpoint endpoint, CancellationToken cancellationToken)
        {
            var pool = new Pool(this, endpoint.Key);
            Pools.Add(pool);
            return Task.FromResult<IMqttPushPool>(pool);
        }
    }

    private sealed class Pool(Publisher owner, string brokerKey) : IMqttPushPool
    {
        public bool Disposed { get; private set; }
        public bool IsConnected => !Disposed;
        public Task<MqttPushDelivery> PublishMeterAsync(IReadOnlyList<NicPublish> messages, CancellationToken cancellationToken)
        {
            owner.Messages.Add((brokerKey, Assert.Single(messages)));
            owner.AfterPublish?.Invoke();
            return Task.FromResult(brokerKey == owner.FailBroker
                ? new MqttPushDelivery(0, 1, "test failure") : new MqttPushDelivery(1, 0));
        }
        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }
}
