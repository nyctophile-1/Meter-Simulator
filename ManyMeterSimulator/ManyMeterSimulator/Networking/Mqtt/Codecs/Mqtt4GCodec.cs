using System.Buffers.Binary;
using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Networking.Mqtt.Codecs;

/// <summary>
/// Direct 4G MQTT — serves BOTH variant c (4G MQTT) and variant d (4G IMG MQTT). HES drives them
/// from one client, one topic pair and one framing format; the difference is meter hardware, not
/// wire protocol (virtual_nics.md §14.1), so one codec covers both and the <see cref="NicType"/>
/// is just a label.
///
/// Node id is in the topic: HES publishes to <c>PollRequest/{nodeId}</c> and subscribes to
/// <c>PollResponse/#</c>, taking <c>topic.Split('/')[1]</c> as the node id.
///
/// <para>
/// Framing is a 6-byte header, identical in both directions, followed by the complete DLMS wrapper
/// frame. All multi-byte framing fields are LITTLE-endian (HES uses BitConverter both ways); the
/// DLMS wrapper inside stays big-endian per IEC 62056-47.
/// </para>
/// <code>
///   offset 0  size 2   total length, LE (payload + 6)
///   offset 2  size 1   total fragments
///   offset 3  size 1   this fragment (1-based)
///   offset 4  size 2   frameId, LE   ← echoed back; HES correlates the reply with it
///   offset 6  size n   DLMS wrapper frame (8-byte WPDU header + APDU)
/// </code>
/// </summary>
public sealed class Mqtt4GCodec : INicCodec
{
    public const string RequestTopicPrefix = "PollRequest/";
    public const string ResponseTopicPrefix = "PollResponse/";

    /// <summary>Length of the framing header, both directions. HES calls this PullHeaderLength = 6.</summary>
    public const int HeaderLength = 6;

    public Mqtt4GCodec(NicType nic)
    {
        if (nic is not (NicType.Mqtt4G or NicType.Mqtt4GImg))
        {
            throw new ArgumentOutOfRangeException(nameof(nic), nic, "This codec serves the direct 4G NICs only.");
        }

        Nic = nic;
    }

    public NicType Nic { get; }

    public IReadOnlyList<string> RequestTopicFilters { get; } = new[] { RequestTopicPrefix + "#" };

    /// <summary>The topic a reply for this node is published on.</summary>
    public static string ResponseTopic(string nodeId) => ResponseTopicPrefix + nodeId;

    public bool TryRoute(NicEnvelope envelope, out NicRoute route)
    {
        route = default;

        // "PollRequest/{nodeId}" — mirrors how HES reads our responses back.
        string[] parts = envelope.Topic.Split('/');
        if (parts.Length < 2 || parts[1].Length == 0)
        {
            return false;
        }

        route = new NicRoute(parts[1]);
        return true;
    }

    public NicDecodeResult Decode(NicEnvelope envelope, NicRoute route)
    {
        ReadOnlySpan<byte> payload = envelope.Payload;

        if (payload.Length < HeaderLength)
        {
            return NicDecodeResult.Malformed($"{payload.Length} bytes is shorter than the {HeaderLength}-byte header");
        }

        int totalFragments = payload[2];
        int thisFragment = payload[3];
        ushort frameId = BinaryPrimitives.ReadUInt16LittleEndian(payload[4..6]);

        // HES defends against a NIC that emits these two the other way round, so we mirror it
        // rather than rejecting a packet HES itself would have accepted.
        if (thisFragment > totalFragments)
        {
            (totalFragments, thisFragment) = (thisFragment, totalFragments);
        }

        if (totalFragments > 1)
        {
            // HES hardcodes totalFragments = 1 on this path (its splitting loop is commented out),
            // so this should be unreachable in practice. Reported as Unsupported rather than
            // Malformed so a deferred feature is never mistaken for a decoding bug.
            return NicDecodeResult.Unsupported(
                $"fragmented request ({thisFragment}/{totalFragments}) — NIC-level reassembly is not implemented", frameId);
        }

        return NicDecodeResult.Complete(payload[HeaderLength..].ToArray(), frameId);
    }

    public IReadOnlyList<NicPublish> Encode(
        NicEnvelope request, NicRoute route, ushort frameId, ReadOnlyMemory<byte> dlmsResponse)
    {
        if (dlmsResponse.IsEmpty)
        {
            // The brain had nothing to say (e.g. a request it silently absorbed). Publishing an
            // empty frame would look like a malformed meter rather than a quiet one.
            return Array.Empty<NicPublish>();
        }

        return new[] { new NicPublish(ResponseTopic(route.NodeId), BuildFrame(frameId, dlmsResponse.Span)) };
    }

    /// <summary>
    /// Builds a single-fragment message: the 6-byte header then the DLMS wrapper frame verbatim.
    ///
    /// Always one fragment. The simulator has no radio to constrain it, and HES's reassembly is
    /// count-based with the length field never validated — so a single large message takes the
    /// short-circuit path in its parser. (Gurux already segments big reads at the DLMS layer, so
    /// individual frames are small anyway.)
    /// </summary>
    public static byte[] BuildFrame(ushort frameId, ReadOnlySpan<byte> dlmsFrame)
    {
        var buffer = new byte[HeaderLength + dlmsFrame.Length];

        // HES writes payload.Length + 6 here, i.e. the length INCLUDING this header. It only ever
        // reads byte 0 back, and only for bookkeeping — but we write what it writes.
        BinaryPrimitives.WriteUInt16LittleEndian(buffer, (ushort)(dlmsFrame.Length + HeaderLength));
        buffer[2] = 1;   // total fragments
        buffer[3] = 1;   // this fragment (1-based)
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(4), frameId);
        dlmsFrame.CopyTo(buffer.AsSpan(HeaderLength));

        return buffer;
    }
}
