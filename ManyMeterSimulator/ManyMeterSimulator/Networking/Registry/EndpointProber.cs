using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Options;
using MQTTnet;

namespace ManyMeterSimulator.Networking.Registry;

/// <summary>
/// Reachability checks for registry endpoints — "we accept them only if we connect successfully"
/// (network_registry.md §4).
///
/// <para>
/// One prober serves both the add dialog and the health monitor on purpose: if the accept-time
/// check and the ongoing check could differ, a row could be accepted by one and permanently
/// reported red by the other, with nothing to explain the contradiction.
/// </para>
/// </summary>
public sealed class EndpointProber
{
    private readonly ILogger<EndpointProber> _logger;
    private readonly NicsOptions _nics;
    private readonly TcpOptions _tcp;

    public EndpointProber(ILogger<EndpointProber> logger, IOptions<NicsOptions> nics, IOptions<TcpOptions> tcp)
    {
        _logger = logger;
        _nics = nics.Value;
        _tcp = tcp.Value;
    }

    /// <summary>
    /// Connects to the broker with the supplied credentials and disconnects again.
    ///
    /// <para>
    /// The client id is disposable and probe-specific. It must never collide with a live NIC
    /// client's: brokers evict the older session on a duplicate id, so a careless probe would knock
    /// the running fleet off the broker it is testing.
    /// </para>
    /// </summary>
    public async Task<ProbeResult> TestBrokerAsync(
        BrokerEndpoint broker, int timeoutSeconds = 10, CancellationToken cancellationToken = default)
    {
        // Built through the same mapper the live client uses, so the probe tries EXACTLY the
        // credentials a real connection would. Anything narrower and the page could report an
        // endpoint red that the fleet is happily talking to.
        MqttBrokerOptions connection = _nics.ConnectionFor(broker);

        List<MqttCredential> candidates = connection.Credentials.Count > 0
            ? connection.Credentials
            : new List<MqttCredential> { new() { Name = "anonymous" } };

        var stopwatch = Stopwatch.StartNew();
        string? lastError = null;

        foreach (MqttCredential credential in candidates)
        {
            ProbeResult attempt = await TryConnectAsync(broker, connection, credential, timeoutSeconds, cancellationToken);
            if (attempt.Ok)
            {
                stopwatch.Stop();
                return ProbeResult.Success(stopwatch.Elapsed);
            }

            lastError = attempt.Error;
        }

        stopwatch.Stop();
        return ProbeResult.Fail(lastError ?? "No credentials configured.", stopwatch.Elapsed);
    }

    private async Task<ProbeResult> TryConnectAsync(
        BrokerEndpoint broker,
        MqttBrokerOptions connection,
        MqttCredential credential,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        MqttClientOptionsBuilder builder = new MqttClientOptionsBuilder()
            .WithClientId($"{connection.ClientIdPrefix}-probe-{Guid.NewGuid():N}")
            .WithTcpServer(connection.Host, connection.Port)
            .WithCleanSession(true)
            .WithTlsOptions(o => o.UseTls(connection.UseTls));

        if (!string.IsNullOrEmpty(credential.Username))
        {
            builder = builder.WithCredentials(credential.Username, credential.Password);
        }

        using IMqttClient client = new MqttClientFactory().CreateMqttClient();

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

            MqttClientConnectResult result = await client.ConnectAsync(builder.Build(), timeout.Token);

            if (result.ResultCode != MqttClientConnectResultCode.Success)
            {
                return ProbeResult.Fail($"Broker refused the connection: {result.ResultCode}", TimeSpan.Zero);
            }

            // Best-effort tidy disconnect; a broker that took the CONNECT has already answered the
            // only question being asked, so a failure to close cleanly is not a probe failure.
            try
            {
                await client.DisconnectAsync(cancellationToken: CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Probe of {Broker} could not disconnect cleanly.", broker.Describe());
            }

            return ProbeResult.Success(TimeSpan.Zero);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return ProbeResult.Fail($"Timed out after {timeoutSeconds}s.", TimeSpan.Zero);
        }
        catch (Exception ex)
        {
            // The real message, not a generic "could not connect" — a wrong password and an
            // unroutable host are the two most common causes and they need different fixes.
            return ProbeResult.Fail(ex.Message, TimeSpan.Zero);
        }
    }

    /// <summary>
    /// Opens a TCP connection to the HES push listener and closes it. Nothing is sent: a stray byte
    /// would reach a real listener as a malformed push, so a completed handshake is deliberately the
    /// entire assertion.
    /// </summary>
    public async Task<ProbeResult> TestPushTargetAsync(
        PushTargetEndpoint target, int timeoutSeconds = 10, CancellationToken cancellationToken = default)
    {
        if (!PushTargetEndpoint.TryParseAddress(target.Address, out IPAddress? address, out string error))
        {
            return ProbeResult.Fail(error, TimeSpan.Zero);
        }

        var stopwatch = Stopwatch.StartNew();

        // Bind the SAME source address a real push would leave from, rather than letting the OS
        // pick one. On a prefix-only ENI (the EQA instance) the host has NO global IPv6 address of
        // its own — only the delegated meter prefix — so an unbound IPv6 connect has no source to
        // select and fails instantly, reporting a healthy endpoint as unreachable. Push never hits
        // that because TcpPushSender binds the meter's address; the probe has to do the same or it
        // is testing a path the simulator never uses.
        using TcpClient client = CreateProbeClient(address!);

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

            await client.ConnectAsync(address!, target.Port, timeout.Token);
            stopwatch.Stop();
            return ProbeResult.Success(stopwatch.Elapsed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            stopwatch.Stop();
            return ProbeResult.Fail($"Timed out after {timeoutSeconds}s — nothing is listening on {target.Destination}.", stopwatch.Elapsed);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return ProbeResult.Fail(ex.Message, stopwatch.Elapsed);
        }
    }

    /// <summary>
    /// A client bound to the first meter address in the configured prefix, when the destination is
    /// IPv6 and that bind is possible. Falls back to an unbound client — a bind only fails when the
    /// meter prefix isn't locally routed on this host, and in that case an unbound attempt still
    /// gives the operator a real result instead of a bind error they can't act on.
    /// </summary>
    private TcpClient CreateProbeClient(IPAddress destination)
    {
        if (destination.AddressFamily == AddressFamily.InterNetworkV6)
        {
            try
            {
                IPAddress source = MeterAddressing.ComputeAddress(_tcp.AddressPrefix, 1);
                return new TcpClient(new IPEndPoint(source, 0));
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex,
                    "Could not bind a meter source address from prefix {Prefix} for the probe; " +
                    "falling back to the host's default source.", _tcp.AddressPrefix);
            }
        }

        return new TcpClient(destination.AddressFamily);
    }
}

/// <summary>Outcome of one reachability check.</summary>
public readonly record struct ProbeResult(bool Ok, string? Error, TimeSpan Elapsed)
{
    public static ProbeResult Success(TimeSpan elapsed) => new(true, null, elapsed);

    public static ProbeResult Fail(string error, TimeSpan elapsed) => new(false, error, elapsed);
}
