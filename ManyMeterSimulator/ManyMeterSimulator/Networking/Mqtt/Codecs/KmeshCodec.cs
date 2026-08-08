using Google.Protobuf;
using ManyMeterSimulator.KimbalSpecifics.Kmesh;
using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Networking.Mqtt.Codecs;

/// <summary>
/// RF MQTT Kmesh (virtual_nics.md §14.3). The simplest of the three on the wire and the least like
/// the others: there is **no byte framing at all**. The DLMS wrapper frame sits directly in a
/// protobuf <c>bytes</c> field, and fragmentation — when it exists — lives in
/// <c>FragmentInfo</c> inside the message rather than in a header.
///
/// Note this uses Google.Protobuf while Wirepas uses protobuf-net; they are different stacks with
/// different APIs, which is why both packages are referenced.
///
/// HES's <c>PullHeaderLength == 7</c> for Kmesh templates is a DISCRIMINATOR, not a length — there
/// are no seven header bytes to strip. Reading it as a length is the obvious trap here.
/// </summary>
public sealed class KmeshCodec : INicCodec
{
    public NicType Nic => NicType.MqttKmesh;

    public IReadOnlyList<string> RequestTopicFilters { get; } = new[] { NicTopics.KmeshRequestFilter };

    public NicTopicPlan TopicPlan { get; } = new(
        Subscribe: NicTopics.KmeshRequestFilter,
        NodeIdSource: "protobuf NodeRequest.NodeId",
        Publish: "gateway/pull/response/meter/{gatewayId}/{nodeId}, gateway echoed from the request",
        HesExpects: "gateway/pull/response/meter/+/#; the + is the gateway id and the tail is not read",
        Framing: "none — Response.Payload IS the DLMS wrapper frame verbatim; FragInfo 1/1");

    public bool TryRoute(NicEnvelope envelope, out NicRoute route)
    {
        route = default;

        NodeRequest? request = TryParse(envelope.Payload);
        if (request is null || request.NodeId == 0)
        {
            return false;
        }

        // Parsed once here and carried forward so Decode does not repeat the work.
        route = new NicRoute(request.NodeId.ToString(), request);
        return true;
    }

    public NicDecodeResult Decode(NicEnvelope envelope, NicRoute route)
    {
        NodeRequest? request = route.Parsed as NodeRequest ?? TryParse(envelope.Payload);
        Request? inner = request?.Request;

        if (inner is null)
        {
            return NicDecodeResult.Malformed("no Request in NodeRequest");
        }

        var frameId = (ushort)inner.RequestId;

        if (inner.Payload is null || inner.Payload.Length == 0)
        {
            return NicDecodeResult.Malformed("empty Request.Payload");
        }

        // Requests are never fragmented on this path — HES builds one NodeRequest and publishes it
        // once — but honour FragInfo if it ever appears rather than silently truncating.
        if (inner.FragInfo is { TotalFrag: > 1 })
        {
            return NicDecodeResult.Unsupported(
                $"fragmented Kmesh request ({inner.FragInfo.ThisFrag}/{inner.FragInfo.TotalFrag}) — reassembly not implemented",
                frameId);
        }

        // The payload IS the DLMS wrapper frame — nothing to strip.
        return NicDecodeResult.Complete(inner.Payload.ToByteArray(), frameId);
    }

    public IReadOnlyList<NicPublish> Encode(
        NicEnvelope request, NicRoute route, ushort frameId, ReadOnlyMemory<byte> dlmsResponse)
    {
        if (dlmsResponse.IsEmpty)
        {
            return Array.Empty<NicPublish>();
        }

        NodeRequest? incoming = route.Parsed as NodeRequest;

        // Echo the gateway the request arrived through rather than inventing one: it is what HES
        // recorded in its routing table for this node, and it is part of the response topic.
        string gatewayId = incoming?.Request?.GatewayId is { Length: > 0 } fromRequest
            ? fromRequest
            : GatewayIdFromTopic(request.Topic);

        var response = new NodeResponse
        {
            Header = new CommonHeader
            {
                NodeAddr = uint.Parse(route.NodeId),
                GatewayId = gatewayId,
                TraveltimeMs = 0,
                EpochMs = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            },
            Response = new Response
            {
                ResponseId = frameId,   // HES correlates the command on (meterNo, frameId)
                RespType = RequestType.KapDlmsWraperPullResponseData,
                Payload = ByteString.CopyFrom(dlmsResponse.Span),
                FragInfo = new FragmentInfo { ThisFrag = 1, TotalFrag = 1 },
            },
        };

        string topic = string.Format(NicTopics.KmeshResponseFormat, gatewayId, route.NodeId);
        return new[] { new NicPublish(topic, response.ToByteArray()) };
    }

    /// <summary>gateway/pull/request/meter/{gatewayId}</summary>
    private static string GatewayIdFromTopic(string topic)
    {
        string[] parts = topic.Split('/');
        return parts.Length > 4 ? parts[4] : string.Empty;
    }

    private static NodeRequest? TryParse(byte[] payload)
    {
        try
        {
            return NodeRequest.Parser.ParseFrom(payload);
        }
        catch
        {
            // Not a NodeRequest — the topic may carry other traffic. Treated as "not ours".
            return null;
        }
    }
}
