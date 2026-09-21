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
    private long _connecting, _active, _peak, _opened, _connectFailures, _peerClosed, _waitExpired, _closeErrors, _payloadsWritten;

    public TcpPushConnectionSnapshot Connections => new(
        Interlocked.Read(ref _connecting), Interlocked.Read(ref _active), Interlocked.Read(ref _peak),
        Interlocked.Read(ref _opened), Interlocked.Read(ref _connectFailures), Interlocked.Read(ref _peerClosed),
        Interlocked.Read(ref _waitExpired), Interlocked.Read(ref _closeErrors), Interlocked.Read(ref _payloadsWritten));

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
        CancellationToken cancellationToken = default, Action<int>? deliveryConfirmed = null,
        int waitForPeerCloseSeconds = 0, TcpPushConnectionGroup? connections = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!TryParseDestination(destination, defaultPort, out string host, out int port))
        {
            _logger.LogWarning("Push {Meter}: bad destination '{Destination}'", meterNo, destination);
            return new PushDeliveryResult(0, payloads.Count, $"Invalid TCP push destination '{destination}'.");
        }

        if (payloads.Count == 0)
        {
            return new PushDeliveryResult(0, 0);
        }

        // All frames for this meter share one source-bound connection.
        string? sourceError = source is null ? "The meter has no source IP assigned."
            : $"Meter source {source} cannot bind to destination {host}:{port} (address family mismatch or non-IP destination).";
        if (CanBindSource(source, host))
        {
            var bound = await TryConnectAndWriteAsync(
                meterNo, source, host, port, payloads, bindSource: true, cancellationToken, deliveryConfirmed, waitForPeerCloseSeconds, connections);
            if (bound.Connected)
            {
                return bound.Result;
            }

            sourceError = bound.Result.Error;
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
            return new PushDeliveryResult(0, payloads.Count, sourceError);
        }

        // Opt-in fallback: the sim server's default source. The push lands but carries no meter
        // identity, so it is warned on every meter, every time — this is a bring-up crutch only.
        var fallback = await TryConnectAndWriteAsync(
            meterNo, source, host, port, payloads, bindSource: false, cancellationToken, deliveryConfirmed, waitForPeerCloseSeconds, connections);
        if (fallback.Connected)
        {
            _logger.LogWarning(
                "Push {Meter}: delivered to {Host}:{Port} from the sim server's default address, NOT " +
                "the meter's own {Source} — the HES push server cannot tell which meter this is. " +
                "Push:RequireMeterSourceIp is off.",
                meterNo, host, port, source is null ? "(none assigned)" : source);
            return fallback.Result;
        }

        return fallback.Result;
    }

    /// <summary>
    /// Opens one socket and writes every payload down it. Reports the failing stage and whether
    /// connect succeeded, so fallback never resends payloads after a partial write.
    /// </summary>
    private async Task<(PushDeliveryResult Result, bool Connected)> TryConnectAndWriteAsync(
        string meterNo, IPAddress? source, string host, int port,
        IReadOnlyList<byte[]> payloads, bool bindSource, CancellationToken cancellationToken,
        Action<int>? deliveryConfirmed, int waitForPeerCloseSeconds, TcpPushConnectionGroup? connections)
    {
        TcpClient client;
        try
        {
            client = bindSource ? new TcpClient(new IPEndPoint(source!, 0)) : NewDefaultClient(host);
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _connectFailures);
            _logger.LogDebug("Push {Meter}: socket open failed: {Message}", meterNo, ex.Message);
            return (new(0, payloads.Count, $"TCP socket bind/open failed for {meterNo} from {source} to {host}:{port}: {ex.Message}"), false);
        }

        bool connected = false;
        bool handedOff = false;
        try
        {
            Interlocked.Increment(ref _connecting);
            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _options.ConnectTimeoutSeconds)));
                await client.ConnectAsync(host, port, connectCts.Token);
                connected = true;
                Interlocked.Increment(ref _opened);
                long active = Interlocked.Increment(ref _active);
                long peak = Interlocked.Read(ref _peak);
                while (active > peak)
                {
                    long previous = Interlocked.CompareExchange(ref _peak, active, peak);
                    if (previous == peak)
                    {
                        break;
                    }

                    peak = previous;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _connectFailures);
                string detail = ex is OperationCanceledException ? $"timed out after {_options.ConnectTimeoutSeconds}s" : ex.Message;
                _logger.LogDebug("Push {Meter}: connect failed: {Message}", meterNo, detail);
                return (new(0, payloads.Count, $"TCP connect failed for {meterNo} from {(bindSource ? source?.ToString() : "default source")} to {host}:{port}: {detail}"), false);
            }
            finally
            {
                Interlocked.Decrement(ref _connecting);
            }

            var result = await WritePayloadsAsync(client, meterNo, host, port, payloads, cancellationToken, deliveryConfirmed);
            if (result.Sent > 0)
            {
                if (result.Failed == 0 && waitForPeerCloseSeconds > 0)
                {
                    if (connections is not null)
                    {
                        connections.Track(token => CloseAfterWriteAsync(client, waitForPeerCloseSeconds, token));
                        handedOff = true;
                    }
                    else
                    {
                        try
                        {
                            await WaitForPeerCloseAsync(client.GetStream(), waitForPeerCloseSeconds, cancellationToken);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                        {
                            throw new PushCanceledException(result.Sent, result.Failed, cancellationToken);
                        }
                    }
                }
                else
                {
                    try
                    {
                        client.Client.Shutdown(SocketShutdown.Send);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug("Push {Meter}: shutdown after send failed: {Message}", meterNo, ex.Message);
                    }
                }
            }

            return (result, true);
        }
        finally
        {
            if (!handedOff)
            {
                client.Dispose();
                if (connected)
                {
                    Interlocked.Decrement(ref _active);
                }
            }
        }
    }

    private async Task CloseAfterWriteAsync(TcpClient client, int seconds, CancellationToken token)
    {
        try
        {
            await WaitForPeerCloseAsync(client.GetStream(), seconds, token);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _closeErrors);
            _logger.LogDebug(ex, "TCP post-write connection close failed");
        }
        finally
        {
            client.Dispose();
            Interlocked.Decrement(ref _active);
        }
    }

    private async Task<PushDeliveryResult> WritePayloadsAsync(TcpClient client, string meterNo, string host, int port,
        IReadOnlyList<byte[]> payloads, CancellationToken cancellationToken, Action<int>? deliveryConfirmed)
    {
        var sendTimeout = TimeSpan.FromSeconds(Math.Max(1, _options.SendTimeoutSeconds));
        var stream = client.GetStream();
        int sent = 0;
        string? error = null;

        for (int i = 0; i < payloads.Count; i++)
        {
            try
            {
                using var writeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                writeCts.CancelAfter(sendTimeout);
                await stream.WriteAsync(payloads[i], writeCts.Token);
                sent++;
                Interlocked.Increment(ref _payloadsWritten);
                deliveryConfirmed?.Invoke(i);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw new PushCanceledException(sent, payloads.Count - sent, cancellationToken);
            }
            catch (Exception ex)
            {
                string detail = ex is OperationCanceledException ? $"timed out after {_options.SendTimeoutSeconds}s" : ex.Message;
                error = $"TCP write {i + 1}/{payloads.Count} failed for {meterNo} to {host}:{port}: {detail}";
                _logger.LogDebug("Push {Meter}: write failed: {Message}", meterNo, detail);
                break;
            }
        }

        return new(sent, payloads.Count - sent, error);
    }

    private async Task WaitForPeerCloseAsync(NetworkStream stream, int seconds, CancellationToken cancellationToken)
    {
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        wait.CancelAfter(TimeSpan.FromSeconds(seconds));
        var buffer = new byte[256];

        try
        {
            while (await stream.ReadAsync(buffer, wait.Token) != 0)
            {
                // Drain any response while waiting for the peer's FIN.
            }

            Interlocked.Increment(ref _peerClosed);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            Interlocked.Increment(ref _waitExpired);
        }
        catch (IOException ex)
        {
            Interlocked.Increment(ref _closeErrors);
            _logger.LogDebug("TCP peer-close wait ended with a socket error: {Message}", ex.Message);
        }

        cancellationToken.ThrowIfCancellationRequested();
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
public readonly record struct PushDeliveryResult(int Sent, int Failed, string? Error = null);

public sealed record TcpPushConnectionSnapshot(long Connecting, long Active, long PeakActive,
    long Opened, long ConnectFailures, long PeerClosed, long WaitExpired, long CloseErrors, long PayloadsWritten);
