using System.Net;
using System.Net.Sockets;

namespace ManyMeterSimulator.Networking.Push;

/// <summary>
/// Sends a TCP meter's push payloads to the HES push listener.
///
/// <para>
/// This is the transport half of push that used to live inside the DLMS session: the session now
/// only ENCODES a push (<c>DLMSServerSession.BuildPushPayloads</c>), and this decides where and how
/// it goes on the wire — which is a NIC concern, not a meter one. The MQTT NICs have their own
/// sender (publish to a broker topic); this one opens a socket.
/// </para>
///
/// <para>
/// The socket originates from the meter's OWN address so HES correlates the push to the right meter
/// by source IP — a push from meter ABC leaves from ABC's IP, the same IP HES pulls from. When that
/// address cannot reach the destination (a ULA dev prefix pushing to an external HES: the private
/// source has no route out), it falls back to the host's default source so a test push still lands,
/// warning that source-IP correlation is then unavailable. In production the meter prefix is really
/// routed, so the bound source is used and there is no fallback.
/// </para>
/// </summary>
public sealed class TcpPushSender
{
    private readonly ILogger<TcpPushSender> _logger;

    public TcpPushSender(ILogger<TcpPushSender> logger) => _logger = logger;

    /// <summary>
    /// Sends every payload for one meter to <paramref name="destination"/> ("ip", "ip:port" or
    /// "[ipv6]:port"). Returns how many payloads were delivered and how many failed.
    /// </summary>
    public PushDeliveryResult Send(
        string meterNo,
        IPAddress? source,
        string destination,
        int defaultPort,
        IReadOnlyList<byte[]> payloads,
        CancellationToken cancellationToken = default)
    {
        if (!TryParseDestination(destination, defaultPort, out string host, out int port))
        {
            _logger.LogWarning("Push {Meter}: bad destination '{Destination}'", meterNo, destination);
            return new PushDeliveryResult(0, payloads.Count);
        }

        int sent = 0, failed = 0;
        foreach (byte[] payload in payloads)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            if (SendOne(meterNo, source, host, port, payload))
            {
                sent++;
            }
            else
            {
                failed++;
            }
        }

        return new PushDeliveryResult(sent, failed);
    }

    private bool SendOne(string meterNo, IPAddress? source, string host, int port, byte[] payload)
    {
        // Preferred: originate from the meter's own address. Tried once, not per-retry — if that
        // address cannot reach this destination it never will (it times out, it is not transient),
        // so retrying it only delays the fallback.
        bool canBindSource = CanBindSource(source, host);
        if (canBindSource && TryConnectAndWrite(meterNo, source, host, port, payload, bindSource: true))
        {
            return true;
        }

        // Fallback: the host's default (routable) source. Production never gets here — the meter
        // prefix is really routed, so the bound send above succeeds. This exists for testing against
        // an external HES from a ULA dev prefix, where the private source has no route out.
        if (TryConnectAndWrite(meterNo, source, host, port, payload, bindSource: false))
        {
            if (canBindSource)
            {
                _logger.LogWarning(
                    "Push {Meter}: reached {Host}:{Port} from the host's default address, not the " +
                    "meter's own {Source} — HES cannot correlate this push by source IP. The meter " +
                    "prefix is not routable to this destination from here (expected when a ULA dev " +
                    "prefix pushes to an external server; in production the prefix is really routed).",
                    meterNo, host, port, source);
            }

            return true;
        }

        return false;
    }

    private bool TryConnectAndWrite(
        string meterNo, IPAddress? source, string host, int port, byte[] payload, bool bindSource)
    {
        try
        {
            using TcpClient client = bindSource
                ? new TcpClient(new IPEndPoint(source!, 0))
                : NewDefaultClient(host);

            if (!client.ConnectAsync(host, port).Wait(TimeSpan.FromSeconds(5)))
            {
                throw new TimeoutException("connect timeout");
            }

            using NetworkStream stream = client.GetStream();
            stream.Write(payload, 0, payload.Length);
            stream.Flush();

            _logger.LogDebug(
                "Push {Meter}: sent {Bytes} bytes to {Host}:{Port} {From}",
                meterNo, payload.Length, host, port, bindSource ? $"from {source}" : "from the host's default source");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(
                "Push {Meter}: {Which} attempt to {Host}:{Port} failed: {Message}",
                meterNo, bindSource ? "source-bound" : "default-source", host, port, ex.Message);
            return false;
        }
    }

    /// <summary>
    /// True when the meter's own address can be the push source: one is known and its family matches
    /// the destination's. A family mismatch (IPv6 meter → IPv4 target) can't bind.
    /// </summary>
    private static bool CanBindSource(IPAddress? source, string host) =>
        source != null
        && IPAddress.TryParse(host, out IPAddress? dest)
        && dest.AddressFamily == source.AddressFamily;

    /// <summary>
    /// A default-source client in the DESTINATION's family. The parameterless <c>new TcpClient()</c>
    /// is IPv4-only and cannot connect to an IPv6 destination at all — which every push target is.
    /// </summary>
    private static TcpClient NewDefaultClient(string host) =>
        IPAddress.TryParse(host, out IPAddress? dest)
            ? new TcpClient(dest.AddressFamily)
            : new TcpClient();

    /// <summary>
    /// Splits a destination into host + port:
    ///   "127.0.0.1:7000" → 127.0.0.1 / 7000 · "127.0.0.1" → 127.0.0.1 / defaultPort ·
    ///   "[2406:da1a:..]:7000" → 2406:da1a:.. / 7000 · "2406:da1a:.." → 2406:da1a:.. / defaultPort.
    /// </summary>
    public static bool TryParseDestination(string dest, int defaultPort, out string host, out int port)
    {
        host = string.Empty;
        port = defaultPort;

        if (string.IsNullOrWhiteSpace(dest))
        {
            return false;
        }

        dest = dest.Trim();

        // Bracketed IPv6: [addr] or [addr]:port
        if (dest.StartsWith('['))
        {
            int close = dest.IndexOf(']');
            if (close < 0)
            {
                return false;
            }

            host = dest.Substring(1, close - 1);
            string rest = dest[(close + 1)..];
            if (rest.StartsWith(':') && int.TryParse(rest[1..], out int p6))
            {
                port = p6;
            }

            return host.Length > 0;
        }

        // One colon → host:port (IPv4/hostname). Zero → bare IPv4/hostname. More → bare IPv6.
        int colons = dest.Count(c => c == ':');
        if (colons == 1)
        {
            string[] parts = dest.Split(':');
            host = parts[0];
            if (int.TryParse(parts[1], out int p))
            {
                port = p;
            }

            return host.Length > 0;
        }

        host = dest;
        return true;
    }
}

/// <summary>Outcome of sending one meter's push payloads.</summary>
public readonly record struct PushDeliveryResult(int Sent, int Failed);
