using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Tests;

public sealed class FakeRoutingGatewayTests
{
    [Theory]
    [InlineData(NicType.Tcp4G, "4/direct_tcp/direct_tcp")]
    [InlineData(NicType.Mqtt4G, "3/direct_4g/direct_4g")]
    [InlineData(NicType.Mqtt4GImg, "3/direct_4g/direct_4g")]
    [InlineData(NicType.MqttWirepas, "2/gate_17_2/sink1")]
    [InlineData(NicType.MqttKmesh, "1/gate_17_2/1")]
    public void TopicContainsStableTransportAndRoute(NicType nic, string route)
    {
        var batch = Batch(nic);

        Assert.Equal("FakeRouting/1002301002/" + route, NicTopics.FakeRouting(batch, 2301002));
        Assert.Equal(NicTopics.FakeRouting(batch, 2301002), NicTopics.FakeRouting(Batch(nic), 2301002));
    }

    [Fact]
    public void MillionMetersHaveExactlyOneThousandGatewaysAndFourBalancedSinks()
    {
        var gateways = new Dictionary<string, int>();
        var sinks = new Dictionary<string, int>();
        var batch = Batch(NicType.MqttWirepas);

        for (long index = batch.StartIndex; index <= batch.EndIndex; index++)
        {
            var route = BatchGatewayAssignment.For(batch.Id, batch.StartIndex, index);
            gateways[route.Gateway] = gateways.GetValueOrDefault(route.Gateway) + 1;
            sinks[route.Sink] = sinks.GetValueOrDefault(route.Sink) + 1;
        }

        Assert.Equal(1000, gateways.Count);
        Assert.All(gateways.Values, count => Assert.Equal(1000, count));
        Assert.Equal(4, sinks.Count);
        Assert.All(sinks.Values, count => Assert.Equal(250000, count));
    }

    [Fact]
    public void SinkDependsOnNodeIdentityAndNotBatchBoundary()
    {
        Assert.Equal(BatchGatewayAssignment.For(1, 1, 12345).Sink,
            BatchGatewayAssignment.For(2, 12300, 12345).Sink);
        Assert.Throws<ArgumentOutOfRangeException>(() => NicTopics.FakeRouting(Batch(NicType.MqttWirepas), 1));
    }

    private static MeterBatch Batch(NicType nic) => new()
    {
        Id = 17,
        Name = "routing",
        TemplateName = "test.xml",
        StartIndex = 2300002,
        Count = 1000000,
        NicType = nic
    };
}
