using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Networking.Mqtt.Codecs;

/// <summary>
/// A codec that subscribes and answers nothing — it exists to get ground truth on the wire before
/// any unwrap logic is written (virtual_nics.md §9, step 1).
///
/// Wraps a real codec so the topic filters and routing are the genuine ones, but the listener
/// treats it as capture-only. Point it at a live HES and every message lands in
/// <c>data/captures/</c> as a golden vector for the Phase E/F/G codecs.
///
/// Deliberately silent: a capture run must not answer HES, or the meter it is impersonating would
/// start behaving like two meters at once.
/// </summary>
public sealed class RawCaptureCodec : INicCodec
{
    private readonly INicCodec _inner;

    public RawCaptureCodec(INicCodec inner) => _inner = inner;

    public NicType Nic => _inner.Nic;

    public IReadOnlyList<string> RequestTopicFilters => _inner.RequestTopicFilters;

    /// <summary>
    /// Delegates to the wrapped codec, but a routing failure is not fatal here — an unroutable
    /// message is still worth capturing, and for the variants whose codec is not written yet it is
    /// the ONLY thing we get. The listener captures first and routes second.
    /// </summary>
    public bool TryRoute(NicEnvelope envelope, out NicRoute route) => _inner.TryRoute(envelope, out route);

    public NicDecodeResult Decode(NicEnvelope envelope, NicRoute route) => _inner.Decode(envelope, route);

    /// <summary>Silent by design — a capture run must never answer HES.</summary>
    public IReadOnlyList<NicPublish> Encode(
        NicEnvelope request, NicRoute route, ushort frameId, ReadOnlyMemory<byte> dlmsResponse) =>
        Array.Empty<NicPublish>();
}

/// <summary>
/// Placeholder for a variant whose wire format is known but whose codec is not written yet
/// (Wirepas, Kmesh — their node id is inside a protobuf payload, so routing needs the real decoder
/// from Phase F/G). Subscribes to the right topics so a capture run collects their traffic; never
/// claims to route.
/// </summary>
public sealed class CaptureOnlyCodec : INicCodec
{
    public CaptureOnlyCodec(NicType nic, params string[] requestTopicFilters)
    {
        Nic = nic;
        RequestTopicFilters = requestTopicFilters;
    }

    public NicType Nic { get; }

    public IReadOnlyList<string> RequestTopicFilters { get; }

    public bool TryRoute(NicEnvelope envelope, out NicRoute route)
    {
        route = default;
        return false;
    }

    public NicDecodeResult Decode(NicEnvelope envelope, NicRoute route) =>
        NicDecodeResult.Unsupported($"{Nic} has no decoder yet — capture only");

    public IReadOnlyList<NicPublish> Encode(
        NicEnvelope request, NicRoute route, ushort frameId, ReadOnlyMemory<byte> dlmsResponse) =>
        Array.Empty<NicPublish>();
}
