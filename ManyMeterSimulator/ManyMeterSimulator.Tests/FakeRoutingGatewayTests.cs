using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Tests;

public sealed class FakeRoutingGatewayTests
{
    [Theory]
    [InlineData(NicType.Tcp4G, "4/direct_tcp_1002/direct_tcp")]
    [InlineData(NicType.Mqtt4G, "3/direct_4g_1002/direct_4g")]
    [InlineData(NicType.Mqtt4GImg, "3/direct_4g_1002/direct_4g")]
    [InlineData(NicType.MqttWirepas, "2/gw_1002/sink1")]
    [InlineData(NicType.MqttKmesh, "1/kgw_1002/1")]
    public void TopicContainsStableTransportAndRoute(NicType nic, string route)
    {
        var batch = Batch(nic);

        Assert.Equal("FakeRouting/1002301002/" + route, NicTopics.FakeRouting(batch, 2301002));
        Assert.Equal(NicTopics.FakeRouting(batch, 2301002), NicTopics.FakeRouting(Batch(nic), 2301002));
    }

    [Fact]
    public void MillionMetersHaveTenThousandGatewayBucketsAndFourBalancedSinks()
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

        Assert.Equal(10000, gateways.Count);
        Assert.All(gateways.Values, count => Assert.Equal(100, count));
        Assert.Equal(4, sinks.Count);
        Assert.All(sinks.Values, count => Assert.Equal(250000, count));
    }

    [Fact]
    public void SinkDependsOnNodeIdentityAndNotBatchBoundary()
    {
        Assert.Equal(BatchGatewayAssignment.For(1, 1, 12345),
            BatchGatewayAssignment.For(2, 12300, 12345));
        Assert.Throws<ArgumentOutOfRangeException>(() => NicTopics.FakeRouting(Batch(NicType.MqttWirepas), 1));
    }

    [Theory]
    [InlineData(1, "0001")]
    [InlineData(9999, "9999")]
    [InlineData(10000, "0000")]
    [InlineData(1341256, "1256")]
    public void GatewaySuffixPreservesFourDigits(long index, string suffix)
    {
        Assert.Equal("direct_tcp_" + suffix, BatchGatewayAssignment.GatewayFor("TCP", index));
        Assert.Equal("direct_4g_" + suffix, BatchGatewayAssignment.GatewayFor("MQTT4G", index));
        Assert.Equal("gw_" + suffix, BatchGatewayAssignment.For(1, 1, index).Gateway);
        Assert.Equal("kgw_" + suffix, BatchGatewayAssignment.ForKmesh(1, 1, index).Gateway);
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
