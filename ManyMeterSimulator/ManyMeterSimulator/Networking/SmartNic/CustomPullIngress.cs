using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Networking.SmartNic;

public enum CustomPullIngressStatus
{
    Complete,
    Unsupported,
    Malformed,
}

/// <summary>All verified facts a later mini-HES command runner needs from a custom request.</summary>
public readonly record struct CustomPullInbound(
    MeterRef Meter,
    MeterBatch Batch,
    CustomPullProtocolProfile Protocol,
    CustomPullRequest Request,
    CommandIntent Intent);

public readonly record struct CustomPullIngressResult(
    CustomPullIngressStatus Status,
    CustomPullInbound? Inbound,
    string Detail)
{
    public bool IsComplete => Status == CustomPullIngressStatus.Complete && Inbound is not null;

    public static CustomPullIngressResult Complete(CustomPullInbound inbound) =>
        new(CustomPullIngressStatus.Complete, inbound, string.Empty);

    public static CustomPullIngressResult Unsupported(string detail) =>
        new(CustomPullIngressStatus.Unsupported, null, detail);

    public static CustomPullIngressResult Malformed(string detail) =>
        new(CustomPullIngressStatus.Malformed, null, detail);
}

/// <summary>
/// Resolves a Wirepas outer address to its provisioned meter before parsing the custom body. The
/// body has no self-describing widths, so parsing it before the batch/template lookup would allow
/// a wrong profile to turn arbitrary bytes into a plausible command.
/// </summary>
public sealed class CustomPullIngress
{
    private readonly MeterRegistry _registry;
    private readonly CustomPullProtocolResolver _protocols;

    public CustomPullIngress(MeterRegistry registry, CustomPullProtocolResolver protocols)
    {
        _registry = registry;
        _protocols = protocols;
    }

    public CustomPullIngressResult Decode(MeterRef meter, ReadOnlySpan<byte> payload)
    {
        if (meter.Nic != NicType.MqttWirepas)
        {
            return CustomPullIngressResult.Unsupported($"custom pull is not available on {meter.Nic}");
        }

        MeterBatch? batch = _registry.GetBatchForIndex(meter.Index);
        if (batch is null)
        {
            return CustomPullIngressResult.Unsupported($"meter {meter.NodeId} is not provisioned in a batch");
        }

        if (batch.NicType != NicType.MqttWirepas)
        {
            return CustomPullIngressResult.Unsupported(
                $"meter {meter.NodeId} belongs to {batch.NicType}, not the Wirepas custom channel");
        }

        if (!_protocols.TryResolve(batch, out CustomPullProtocolProfile protocol, out string profileError))
        {
            return CustomPullIngressResult.Unsupported(profileError);
        }

        if (meter.Index > MaxNodeId(protocol.WireProfile.NodeIdBytes))
        {
            return CustomPullIngressResult.Unsupported(
                $"meter node id {meter.NodeId} does not fit the template's {protocol.WireProfile.NodeIdBytes}-byte field");
        }

        if (!CustomPullRequestParser.TryParse(payload, protocol.WireProfile, out CustomPullRequest request, out string? parseError))
        {
            return CustomPullIngressResult.Malformed(parseError ?? "custom request could not be parsed");
        }

        uint expectedNodeId = checked((uint)meter.Index);
        if (request.FromNodeId != expectedNodeId || request.ToNodeId != expectedNodeId)
        {
            return CustomPullIngressResult.Malformed(
                $"custom request node ids from={request.FromNodeId}, to={request.ToNodeId} do not match outer destination {expectedNodeId}");
        }

        if (!CustomPullCommandDecoder.TryDecode(meter, request, out CommandIntent intent, out string commandError))
        {
            return CustomPullIngressResult.Unsupported(commandError);
        }

        return CustomPullIngressResult.Complete(new CustomPullInbound(meter, batch, protocol, request, intent));
    }

    private static uint MaxNodeId(int width) => width switch
    {
        3 => 0x00FF_FFFF,
        4 => uint.MaxValue,
        _ => 0,
    };
}
