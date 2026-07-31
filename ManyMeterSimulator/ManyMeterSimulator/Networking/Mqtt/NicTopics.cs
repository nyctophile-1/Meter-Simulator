namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// The topics HES actually uses, read out of the pull service (virtual_nics.md §14).
///
/// "Request" is HES → meter (what we subscribe to) and "response" is meter → HES (what we publish
/// to). Note the naming is from the METER's point of view, which is the opposite of how the HES
/// source names them.
/// </summary>
public static class NicTopics
{
    // ── Direct 4G (variants c, d) — node id is IN the topic ──
    public const string Direct4GRequestFilter = "PollRequest/#";
    public const string Direct4GResponsePrefix = "PollResponse/";

    // ── RF Wirepas (variant a) — node id is inside the protobuf payload ──
    // HES publishes to gw-request/send_data/{gatewayId}/{sinkId}.
    public const string WirepasRequestFilter = "gw-request/send_data/#";

    /// <summary>
    /// Wirepas uplink: gw-event/received_data/{gwId}/{sinkId}/{networkAddress}/{srcEp}/{dstEp}.
    /// HES subscribes with endpoints pinned to 3/3 and additionally drops anything whose
    /// protobuf source_endpoint is not 3.
    /// </summary>
    public const string WirepasResponseFormat = "gw-event/received_data/{0}/{1}/{2}/3/3";

    // ── RF Kmesh (variant b) — node id is inside the protobuf payload ──
    // HES publishes to gateway/pull/request/meter/{gatewayId}.
    public const string KmeshRequestFilter = "gateway/pull/request/meter/+";

    /// <summary>
    /// Kmesh uplink. HES subscribes to gateway/pull/response/meter/+/# and never reads past the
    /// gateway id, so the tail is ours to choose; we mirror the node id for legibility.
    /// </summary>
    public const string KmeshResponseFormat = "gateway/pull/response/meter/{0}/{1}";
}
