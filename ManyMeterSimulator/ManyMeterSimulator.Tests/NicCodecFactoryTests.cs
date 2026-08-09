using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Mqtt.Codecs;
using ManyMeterSimulator.Networking.Nic;
using Xunit;

namespace ManyMeterSimulator.Tests;

public class NicCodecFactoryTests
{
    /// <summary>
    /// The reason codecs stopped being DI singletons. <see cref="WirepasCodec"/> reassembles inbound
    /// fragments in per-instance state keyed by (node id, frame id); if two brokers shared one
    /// instance their fragments would interleave into a single buffer, and the corrupted APDU would
    /// look exactly like a codec bug (network_registry.md §5.4).
    /// </summary>
    [Fact]
    public void EachCallReturnsAFreshInstance_SoFragmentStateIsNeverSharedAcrossBrokers()
    {
        var factory = new NicCodecFactory();

        INicCodec? first = factory.Create(NicType.MqttWirepas);
        INicCodec? second = factory.Create(NicType.MqttWirepas);

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.NotSame(first, second);
    }

    [Fact]
    public void ImgResolvesToTheDirect4GCodec()
    {
        var factory = new NicCodecFactory();

        INicCodec? codec = factory.Create(NicType.Mqtt4GImg);

        Assert.IsType<Mqtt4GCodec>(codec);
        Assert.Equal(NicType.Mqtt4G, codec!.Nic);
    }

    [Fact]
    public void EveryMqttTransportHasACodec()
    {
        var factory = new NicCodecFactory();

        foreach (NicType transport in NicCodecFactory.Transports)
        {
            Assert.NotNull(factory.Create(transport));
        }
    }

    [Fact]
    public void TcpHasNone()
    {
        Assert.Null(new NicCodecFactory().Create(NicType.Tcp4G));
    }
}
