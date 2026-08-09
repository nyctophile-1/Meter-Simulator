using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
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

    public EndpointProber(ILogger<EndpointProber> logger) => _logger = logger;

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
        MqttClientOptionsBuilder builder = new MqttClientOptionsBuilder()
            .WithClientId($"nicsim-probe-{Guid.NewGuid():N}")
            .WithTcpServer(broker.Host, broker.Port)
            .WithCleanSession(true)
            .WithTlsOptions(o => o.UseTls(broker.UseTls));

        if (!string.IsNullOrEmpty(broker.Username))
        {
            builder = builder.WithCredentials(broker.Username, broker.Password);
        }

        var stopwatch = Stopwatch.StartNew();
        using IMqttClient client = new MqttClientFactory().CreateMqttClient();

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

            MqttClientConnectResult result = await client.ConnectAsync(builder.Build(), timeout.Token);
            stopwatch.Stop();

            if (result.ResultCode != MqttClientConnectResultCode.Success)
            {
                return ProbeResult.Fail($"Broker refused the connection: {result.ResultCode}", stopwatch.Elapsed);
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

            return ProbeResult.Success(stopwatch.Elapsed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            stopwatch.Stop();
            return ProbeResult.Fail($"Timed out after {timeoutSeconds}s.", stopwatch.Elapsed);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            // The real message, not a generic "could not connect" — a wrong password and an
            // unroutable host are the two most common causes and they need different fixes.
            return ProbeResult.Fail(ex.Message, stopwatch.Elapsed);
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
        using var client = new TcpClient(AddressFamily.InterNetworkV6);

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
}

/// <summary>Outcome of one reachability check.</summary>
public readonly record struct ProbeResult(bool Ok, string? Error, TimeSpan Elapsed)
{
    public static ProbeResult Success(TimeSpan elapsed) => new(true, null, elapsed);

    public static ProbeResult Fail(string error, TimeSpan elapsed) => new(false, error, elapsed);
}
