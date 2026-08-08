using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Mqtt.Codecs;
using ManyMeterSimulator.Networking.Nic;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Routing for the direct-4G NICs. The node id is in the topic, and HES recovers it from OUR
/// responses the same way (<c>topic.Split('/')[1]</c>), so request parsing and response formatting
/// have to agree — these tests pin both ends of that.
/// </summary>
public class Mqtt4GCodecTests
{
    private static readonly Mqtt4GCodec Codec = new(NicType.Mqtt4G);

    private static NicEnvelope Envelope(string topic) =>
        new(topic, Array.Empty<byte>(), DateTimeOffset.UtcNow);

    [Theory]
    [InlineData("PollRequest/1005", "1005")]
    [InlineData("PollRequest/1", "1")]
    [InlineData("PollRequest/0001005", "0001005")]     // zero-padding survives; MeterRef parses it
    public void TryRoute_TakesTheNodeIdFromTheTopic(string topic, string expected)
    {
        Assert.True(Codec.TryRoute(Envelope(topic), out NicRoute route));
        Assert.Equal(expected, route.NodeId);
        Assert.Null(route.Parsed);   // nothing to parse — the id is in the topic
    }

    [Theory]
    [InlineData("PollRequest/")]
    [InlineData("PollRequest")]
    [InlineData("")]
    public void TryRoute_RejectsATopicWithNoNodeId(string topic)
    {
        Assert.False(Codec.TryRoute(Envelope(topic), out _));
    }

    /// <summary>
    /// The round trip that matters: a node id taken off a request topic must produce a response
    /// topic HES parses back to the same id.
    ///
    /// <para>
    /// Only the node id is in the topic. HES reads exactly <c>Split('/')[1]</c> here; its frame-id
    /// read at [2] is commented out, so the topic stays two segments.
    /// </para>
    /// </summary>
    [Fact]
    public void ResponseTopic_IsParsedBackToTheSameNodeIdByHesRules()
    {
        Assert.True(Codec.TryRoute(Envelope("PollRequest/4242"), out NicRoute route));

        string responseTopic = Mqtt4GCodec.ResponseTopic(route.NodeId);

        Assert.Equal("PollResponse/4242", responseTopic);
        Assert.Equal(route.NodeId, responseTopic.Split('/')[1]);   // exactly what HES does
    }

    /// <summary>
    /// The frame id is HES's correlation half of <c>(meterNo, frameId)</c> and is opaque to us, so
    /// it must come back exactly as it arrived, at bytes 4..5 — which is where
    /// <c>IsCompletePacketDirectDLMS</c> reads it on the single-fragment path.
    ///
    /// <para>
    /// Asserted on the raw BYTES, not the parsed value: we echo the two bytes we were given, so the
    /// round trip holds whatever endianness HES uses at either end. A lookup miss here is a silent
    /// <c>return</c> in HES with no log line at all, so there is no downstream signal to catch it.
    /// </para>
    /// </summary>
    [Fact]
    public void Encode_EchoesTheRequestFrameIdBytesVerbatimIntoTheHeader()
    {
        byte[] requestFrameIdBytes = [0xC5, 0x01];   // frameId 453 as HES put it on the wire

        var request = new NicEnvelope(
            "PollRequest/537",
            [0x2D, 0x00, 0x01, 0x01, requestFrameIdBytes[0], requestFrameIdBytes[1], 0x00, 0x01],
            DateTimeOffset.UtcNow);

        Assert.True(Codec.TryRoute(request, out NicRoute route));
        NicDecodeResult decoded = Codec.Decode(request, route);
        Assert.Equal(453, decoded.FrameId);

        NicPublish publish = Codec.Encode(request, route, decoded.FrameId, new byte[] { 0x61, 0x29 })[0];

        Assert.Equal("PollResponse/537", publish.Topic);
        Assert.Equal(requestFrameIdBytes, publish.Payload[4..6]);
    }

    [Fact]
    public void SubscribesToTheRequestTopicOnly_NeverItsOwnResponses()
    {
        string filter = Assert.Single(Codec.RequestTopicFilters);

        Assert.Equal("PollRequest/#", filter);
        Assert.DoesNotContain("PollResponse", filter);   // subscribing to our own replies would loop
    }

    /// <summary>
    /// c and d are wire-identical, so one codec serves both and the NicType is only a label. Guard
    /// it so nobody "fixes" this into two codecs double-subscribing to PollRequest/#.
    /// </summary>
    [Fact]
    public void ServesBothDirect4GVariants_ButNothingElse()
    {
        Assert.Equal(NicType.Mqtt4G, new Mqtt4GCodec(NicType.Mqtt4G).Nic);
        Assert.Equal(NicType.Mqtt4GImg, new Mqtt4GCodec(NicType.Mqtt4GImg).Nic);

        Assert.Throws<ArgumentOutOfRangeException>(() => new Mqtt4GCodec(NicType.MqttWirepas));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Mqtt4GCodec(NicType.Tcp4G));
    }
}

public class NicsOptionsTests
{
    /// <summary>
    /// IMG shares the direct-4G transport. If this ever became identity-mapped, both would get
    /// their own client and every PollRequest would be received — and later answered — twice.
    /// </summary>
    [Fact]
    public void ImgFoldsIntoTheDirect4GTransport()
    {
        Assert.Equal(NicType.Mqtt4G, NicsOptions.TransportFor(NicType.Mqtt4GImg));
        Assert.Equal(NicType.Mqtt4G, NicsOptions.TransportFor(NicType.Mqtt4G));
        Assert.Equal(NicType.MqttWirepas, NicsOptions.TransportFor(NicType.MqttWirepas));
        Assert.Equal(NicType.MqttKmesh, NicsOptions.TransportFor(NicType.MqttKmesh));
    }

    [Fact]
    public void EnabledTransports_ListsOnlyTheSwitchedOnOnes_AndNeverAnImgEntry()
    {
        var options = new NicsOptions
        {
            Mqtt4G = new MqttNicOptions { Enabled = true },
            MqttWirepas = new MqttNicOptions { Enabled = false },
            MqttKmesh = new MqttNicOptions { Enabled = true },
        };

        NicType[] enabled = options.EnabledTransports().ToArray();

        Assert.Equal(new[] { NicType.Mqtt4G, NicType.MqttKmesh }, enabled);
        Assert.DoesNotContain(NicType.Mqtt4GImg, enabled);
    }

    [Fact]
    public void AVariantWithoutItsOwnBrokerUsesTheSharedOne()
    {
        var options = new NicsOptions
        {
            Shared = new SharedNicOptions { Broker = new MqttBrokerOptions { Host = "shared-host" } },
            Mqtt4G = new MqttNicOptions { Enabled = true },
            MqttKmesh = new MqttNicOptions { Enabled = true, Broker = new MqttBrokerOptions { Host = "kmesh-host" } },
        };

        Assert.Equal("shared-host", options.BrokerFor(NicType.Mqtt4G).Host);
        Assert.Equal("shared-host", options.BrokerFor(NicType.Mqtt4GImg).Host);
        Assert.Equal("kmesh-host", options.BrokerFor(NicType.MqttKmesh).Host);
    }
}

public class CaptureOnlyCodecTests
{
    /// <summary>
    /// Wirepas/Kmesh carry the node id inside a protobuf payload, so until Phase F/G they can
    /// subscribe but never claim to route. Capturing an unroutable message is the whole point —
    /// it is the only evidence those variants produce before their decoders exist.
    /// </summary>
    [Fact]
    public void SubscribesButNeverRoutes()
    {
        var codec = new CaptureOnlyCodec(NicType.MqttWirepas, NicTopics.WirepasRequestFilter);

        Assert.Equal(NicType.MqttWirepas, codec.Nic);
        Assert.Equal(new[] { "gw-request/send_data/#" }, codec.RequestTopicFilters);
        Assert.False(codec.TryRoute(new NicEnvelope("gw-request/send_data/gw1/sink1", [1, 2, 3], DateTimeOffset.UtcNow), out _));
    }
}
