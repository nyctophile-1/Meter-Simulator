using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Logging.Abstractions;

namespace ManyMeterSimulator.Tests;

public sealed class MqttRoutingServiceTests
{
    [Theory]
    [InlineData(NicType.Tcp4G, "4")]
    [InlineData(NicType.Mqtt4G, "3")]
    [InlineData(NicType.Mqtt4GImg, "3")]
    [InlineData(NicType.MqttWirepas, "2")]
    [InlineData(NicType.MqttKmesh, "1")]
    public async Task BatchSchedulerRoutingSenderUsesEmptyTransportAwareTopic(NicType nic, string suffix)
    {
        var f = new Fixture();
        var batch = f.Add(nic, "a");
        var sender = new ManyMeterSimulator.Brain.BatchTrafficSender(null!, f.Network, f.Publisher);
        await using (var session = await sender.OpenAsync(batch, BatchTrafficKind.Routing, default))
            await session.SendAsync(batch.StartIndex, default);
        var item = Assert.Single(f.Publisher.Messages);
        Assert.Equal(NicTopics.FakeRouting(batch, batch.StartIndex), item.Message.Topic);
        Assert.Empty(item.Message.Payload);
        Assert.True(Assert.Single(f.Publisher.Pools).Disposed);
    }

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
        Assert.Equal(new[] { "FakeRouting/1000000001/3/direct_4g/direct_4g", "FakeRouting/1000000002/3/direct_4g/direct_4g", "FakeRouting/1000000003/3/direct_4g/direct_4g", "FakeRouting/1000000006/4/direct_tcp/direct_tcp" },
            fixture.Publisher.Messages.Where(m => m.BrokerKey == "a").Select(m => m.Message.Topic));
        Assert.Equal(new[] { "FakeRouting/1000000004/3/direct_4g/direct_4g", "FakeRouting/1000000005/3/direct_4g/direct_4g", "FakeRouting/1000000007/2/gate_4_1/sink2", "FakeRouting/1000000008/1/gate_5_1/3" },
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
        public Task<MqttPushDelivery> PublishMeterAsync(IReadOnlyList<NicPublish> messages, CancellationToken cancellationToken, ManyMeterSimulator.Networking.Mqtt.MqttPublishRateLimiter? rateLimiter = null)
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
