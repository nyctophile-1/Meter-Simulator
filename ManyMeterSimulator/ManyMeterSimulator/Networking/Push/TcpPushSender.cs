using System.Net;
using System.Net.Sockets;
using ManyMeterSimulator.Brain;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Networking.Push;

/// <summary>
/// Sends a TCP meter's push payloads from the sim server to the HES push server.
///
/// <para>
/// This is the transport half of push that used to live inside the DLMS session: the session now
/// only ENCODES a push (<c>DLMSServerSession.BuildPushPayloads</c>), and this decides where and how
/// it goes on the wire — which is a NIC concern, not a meter one. The MQTT NICs have their own
/// sender (publish to a broker topic); this one opens a socket.
/// </para>
///
/// <para>
/// The socket binds its local endpoint to the METER's own assigned IP, because on TCP that source
/// address is the ONLY identity the push carries — it is how the HES push server knows whose data
/// this is. A push from meter ABC leaves from ABC's IP, the same IP HES pulls from.
/// </para>
///
/// <para>
/// If the meter's own address cannot reach the destination, the push FAILS by default
/// (<see cref="PushOptions.RequireMeterSourceIp"/>) rather than quietly going out from the sim
/// server's default address — that would arrive attributed to the wrong meter, with every meter
/// looking identical. The fallback exists only as an explicit opt-in for bring-up.
/// </para>
/// </summary>
public sealed class TcpPushSender
{
    private readonly ILogger<TcpPushSender> _logger;
    private readonly PushOptions _options;

    public TcpPushSender(ILogger<TcpPushSender> logger, IOptions<PushOptions> options)
    {
        _logger = logger;
        _options = options.Value;
    }

    /// <summary>
    /// Sends every payload for one meter to <paramref name="destination"/> ("ip", "ip:port" or
    /// "[ipv6]:port"). Returns how many payloads were delivered and how many failed.
    ///
    /// <para>
    /// Fully async: a push is I/O, and the whole point of a fleet push is that thousands are in
    /// flight at once. The blocking version this replaced parked a thread-pool thread per meter for
    /// the duration of the connect, so raising push concurrency starved the pull listener and the UI
    /// rather than sending faster.
    /// </para>
    /// </summary>
    public async Task<PushDeliveryResult> SendAsync(
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

        if (payloads.Count == 0)
        {
            return new PushDeliveryResult(0, 0);
        }

        // ONE connection for all of this meter's payloads, not one per payload: a real meter opens a
        // socket, sends what it has and hangs up. Reconnecting per payload multiplied both the
        // connect cost and the number of sockets a fleet push lands on the HES by the push-object
        // count — which is exactly the number the HES is being tested on.
        //
        // The meter's OWN assigned IP is the identity of a TCP push. Tried once, not per-retry: if
        // that address cannot reach this destination it never will (it times out, it isn't transient).
        if (CanBindSource(source, host))
        {
            PushDeliveryResult? bound = await TryConnectAndWriteAsync(
                meterNo, source, host, port, payloads, bindSource: true, cancellationToken);
            if (bound is not null)
            {
                return bound.Value;
            }
        }

        // Strict (default): never deliver a push the HES push server would attribute to the wrong
        // meter. A push from the sim server's own address is worse than no push — every meter looks
        // identical and the data lands against the wrong meter, silently.
        if (_options.RequireMeterSourceIp)
        {
            _logger.LogWarning(
                "Push {Meter}: NOT sent. Its own address {Source} could not reach {Host}:{Port}, and " +
                "Push:RequireMeterSourceIp is on — a push from the sim server's default address would " +
                "reach the HES push server with the wrong source IP, which is how it identifies the " +
                "meter. Fix the path for the meter prefix (route + firewall/security-group ingress for " +
                "the prefix on the HES push server side), or set Push:RequireMeterSourceIp=false to " +
                "accept unattributable pushes for bring-up.",
                meterNo, source is null ? "(none assigned)" : source, host, port);
            return new PushDeliveryResult(0, payloads.Count);
        }

        // Opt-in fallback: the sim server's default source. The push lands but carries no meter
        // identity, so it is warned on every meter, every time — this is a bring-up crutch only.
        PushDeliveryResult? fallback = await TryConnectAndWriteAsync(
            meterNo, source, host, port, payloads, bindSource: false, cancellationToken);
        if (fallback is not null)
        {
            _logger.LogWarning(
                "Push {Meter}: delivered to {Host}:{Port} from the sim server's default address, NOT " +
                "the meter's own {Source} — the HES push server cannot tell which meter this is. " +
                "Push:RequireMeterSourceIp is off.",
                meterNo, host, port, source is null ? "(none assigned)" : source);
            return fallback.Value;
        }

        return new PushDeliveryResult(0, payloads.Count);
    }

    /// <summary>
    /// Opens one socket and writes every payload down it. Returns null when the CONNECT failed (the
    /// caller may still have a fallback source worth trying); otherwise the per-payload tally, which
    /// can be partial if the far side died mid-stream.
    /// </summary>
    private async Task<PushDeliveryResult?> TryConnectAndWriteAsync(
        string meterNo, IPAddress? source, string host, int port,
        IReadOnlyList<byte[]> payloads, bool bindSource, CancellationToken cancellationToken)
    {
        TcpClient client;
        try
        {
            client = bindSource ? new TcpClient(new IPEndPoint(source!, 0)) : NewDefaultClient(host);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(
                "Push {Meter}: could not open a {Which} socket for {Host}:{Port}: {Message}",
                meterNo, bindSource ? "source-bound" : "default-source", host, port, ex.Message);
            return null;
        }

        using (client)
        {
            // Socket.SendTimeout governs SYNCHRONOUS sends only — async socket operations are bounded
            // by their cancellation token and nothing else. So both deadlines are linked CTSs, which
            // is also what finally makes a caller's cancellation abort an in-flight connect: the old
            // ConnectAsync(...).Wait(timeout) could not, it abandoned the connect task and left it
            // running against a socket that had already been disposed.
            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _options.ConnectTimeoutSeconds)));
                await client.ConnectAsync(host, port, connectCts.Token);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(
                    "Push {Meter}: {Which} connect to {Host}:{Port} failed: {Message}",
                    meterNo, bindSource ? "source-bound" : "default-source", host, port, ex.Message);
                return null;
            }

            var sendTimeout = TimeSpan.FromSeconds(Math.Max(1, _options.SendTimeoutSeconds));
            NetworkStream stream = client.GetStream();

            int sent = 0;
            for (int i = 0; i < payloads.Count; i++)
            {
                try
                {
                    using var writeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    writeCts.CancelAfter(sendTimeout);

                    await stream.WriteAsync(payloads[i], writeCts.Token);
                    await stream.FlushAsync(writeCts.Token);
                    sent++;
                }
                catch (Exception ex)
                {
                    // A HES that accepts the connection and then stops reading is the failure mode
                    // this bounds: without the write deadline that Write blocked forever and leaked
                    // the thread — and "HES slows down under load" is the scenario being tested.
                    _logger.LogDebug(
                        "Push {Meter}: write {Index}/{Total} to {Host}:{Port} failed: {Message}",
                        meterNo, i + 1, payloads.Count, host, port, ex.Message);
                    break;   // the socket is no longer trustworthy; the rest would fail too
                }
            }

            if (sent > 0)
            {
                // Half-close so the HES sees a clean end-of-push rather than having to infer it from
                // a reset when the socket is disposed below.
                try
                {
                    client.Client.Shutdown(SocketShutdown.Send);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug("Push {Meter}: shutdown after send failed: {Message}", meterNo, ex.Message);
                }

                _logger.LogDebug(
                    "Push {Meter}: sent {Sent}/{Total} payload(s) to {Host}:{Port} {From}",
                    meterNo, sent, payloads.Count, host, port,
                    bindSource ? $"from {source}" : "from the host's default source");
            }

            return new PushDeliveryResult(sent, payloads.Count - sent);
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
