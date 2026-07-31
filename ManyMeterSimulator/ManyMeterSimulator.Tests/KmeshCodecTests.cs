using Google.Protobuf;
using ManyMeterSimulator.KimbalSpecifics.Kmesh;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Mqtt.Codecs;
using ManyMeterSimulator.Networking.Nic;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Kmesh carries the DLMS wrapper frame directly in a protobuf field — no byte framing at all.
/// The trap here is HES's <c>PullHeaderLength == 7</c> for Kmesh templates, which is a
/// DISCRIMINATOR rather than a length: stripping seven bytes would corrupt every payload.
/// </summary>
public class KmeshCodecTests
{
    private static readonly KmeshCodec Codec = new();

    private const string RequestTopic = "gateway/pull/request/meter/GW-7";

    /// <summary>Builds a downlink exactly as HES's PublishRequest does for the Kmesh branch.</summary>
    private static NicEnvelope HesRequest(uint nodeId, byte[] dlms, uint frameId, string gatewayId = "GW-7")
    {
        var request = new NodeRequest
        {
            NodeId = nodeId,
            Request = new Request
            {
                GatewayId = gatewayId,
                RequestId = frameId,
                RequestType = RequestType.KapDlmsWraperPullRequestData,
                Payload = ByteString.CopyFrom(dlms),
            },
        };

        return new NicEnvelope(RequestTopic, request.ToByteArray(), DateTimeOffset.UtcNow);
    }

    [Fact]
    public void Routes_OnTheNodeIdInsideTheProtobuf()
    {
        Assert.True(Codec.TryRoute(HesRequest(511, [1, 2, 3], 42), out NicRoute route));

        Assert.Equal("511", route.NodeId);
        Assert.NotNull(route.Parsed);   // parsed once, reused by Decode
    }

    [Fact]
    public void Ignores_NonProtobufPayloads()
    {
        var junk = new NicEnvelope(RequestTopic, [0xFF, 0xFE, 0xFD, 0xFC, 0xFB], DateTimeOffset.UtcNow);

        Assert.False(Codec.TryRoute(junk, out _));
    }

    /// <summary>
    /// The payload IS the wrapper frame. If anyone ever "strips the 7-byte Kmesh header", this
    /// fails — which is the point.
    /// </summary>
    [Fact]
    public void Decode_TakesThePayloadVerbatim_WithNothingStripped()
    {
        byte[] dlms = [0x00, 0x01, 0x00, 0x10, 0x00, 0x01, 0x00, 0x1F, 0x60, 0x1D, 0xA1, 0x09];

        NicEnvelope envelope = HesRequest(511, dlms, 4299);
        Codec.TryRoute(envelope, out NicRoute route);
        NicDecodeResult result = Codec.Decode(envelope, route);

        Assert.True(result.IsComplete);
        Assert.Equal(dlms, result.DlmsFrame);
        Assert.Equal(4299, result.FrameId);
    }

    [Fact]
    public void Decode_RejectsAnEmptyPayload()
    {
        NicEnvelope envelope = HesRequest(511, [], 1);
        Codec.TryRoute(envelope, out NicRoute route);

        Assert.Equal(NicDecodeStatus.Malformed, Codec.Decode(envelope, route).Status);
    }

    /// <summary>
    /// The round trip HES actually performs: it reads the node from Header.NodeAddr and correlates
    /// the command on Response.ResponseId, so both have to come back correctly.
    /// </summary>
    [Fact]
    public void Encode_ProducesANodeResponseHesCanCorrelate()
    {
        byte[] dlms = [0x61, 0x29, 0xA1, 0x09, 0x06];
        const uint frameId = 4299;

        NicEnvelope envelope = HesRequest(511, [1], frameId);
        Codec.TryRoute(envelope, out NicRoute route);

        NicPublish publish = Codec.Encode(envelope, route, (ushort)frameId, dlms)[0];
        NodeResponse response = NodeResponse.Parser.ParseFrom(publish.Payload);

        Assert.Equal(511u, response.Header.NodeAddr);
        Assert.Equal(frameId, response.Response.ResponseId);
        Assert.Equal(RequestType.KapDlmsWraperPullResponseData, response.Response.RespType);
        Assert.Equal(dlms, response.Response.Payload.ToByteArray());

        // Single fragment — HES's reassembly short-circuits on TotalFrag == 1.
        Assert.Equal(1u, response.Response.FragInfo.ThisFrag);
        Assert.Equal(1u, response.Response.FragInfo.TotalFrag);
    }

    /// <summary>
    /// The gateway must be echoed, not invented: HES's routing table records which gateway a node
    /// is behind, and it is the one part of the response topic HES actually reads.
    /// </summary>
    [Fact]
    public void Encode_EchoesTheRequestsGateway()
    {
        NicEnvelope envelope = HesRequest(511, [1], 1, gatewayId: "GW-ALPHA");
        Codec.TryRoute(envelope, out NicRoute route);

        NicPublish publish = Codec.Encode(envelope, route, 1, new byte[] { 9 })[0];
        NodeResponse response = NodeResponse.Parser.ParseFrom(publish.Payload);

        Assert.Equal("GW-ALPHA", response.Header.GatewayId);
        Assert.StartsWith("gateway/pull/response/meter/GW-ALPHA/", publish.Topic);
    }

    /// <summary>HES subscribes gateway/pull/response/meter/+/# — the + must be the gateway.</summary>
    [Fact]
    public void Encode_PublishesWhereHesSubscribes()
    {
        NicEnvelope envelope = HesRequest(511, [1], 1);
        Codec.TryRoute(envelope, out NicRoute route);

        string topic = Codec.Encode(envelope, route, 1, new byte[] { 9 })[0].Topic;
        string[] parts = topic.Split('/');

        Assert.Equal(new[] { "gateway", "pull", "response", "meter" }, parts[..4]);
        Assert.Equal("GW-7", parts[4]);   // the wildcard segment HES reads as the gateway id
    }

    [Fact]
    public void Encode_SendsNothingWhenTheBrainHadNoReply()
    {
        NicEnvelope envelope = HesRequest(511, [1], 1);
        Codec.TryRoute(envelope, out NicRoute route);

        Assert.Empty(Codec.Encode(envelope, route, 1, ReadOnlyMemory<byte>.Empty));
    }
}
