using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Framing;
using ManyMeterSimulator.MqttBridge;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Networking;

public class TcpNicListenerService : BackgroundService
{
    private readonly ILogger<TcpNicListenerService> _logger;
    private readonly TcpOptions _options;
    private readonly ConnectionRegistry _registry;
    private readonly IMeterSimBridge _bridge;
    private readonly SimulatorMetrics _metrics;
    private readonly MeterRegistry _meterRegistry;
    private readonly TemplateRegistry _templateRegistry;
    private readonly NetworkDelaySettings _networkDelay;
    private readonly IHostApplicationLifetime _appLifetime;

    // Deliberately NOT the same token ExecuteAsync receives: that one is cancelled the instant
    // host shutdown starts (which is correct for "stop accepting new connections" immediately),
    // but in-flight sessions should get a bounded grace window to finish their current exchange
    // rather than being cut off mid-flight. This token is only cancelled once that window elapses
    // (or once every session has already finished on its own).
    private readonly CancellationTokenSource _sessionShutdownCts = new();
    private readonly ConcurrentBag<Task> _connectionHandlerTasks = new();

    private Socket? _listenSocket;

    public TcpNicListenerService(
        ILogger<TcpNicListenerService> logger,
        IOptions<TcpOptions> options,
        ConnectionRegistry registry,
        IMeterSimBridge bridge,
        SimulatorMetrics metrics,
        MeterRegistry meterRegistry,
        TemplateRegistry templateRegistry,
        NetworkDelaySettings networkDelay,
        IHostApplicationLifetime appLifetime)
    {
        _logger = logger;
        _options = options.Value;
        _registry = registry;
        _bridge = bridge;
        _metrics = metrics;
        _meterRegistry = meterRegistry;
        _templateRegistry = templateRegistry;
        _networkDelay = networkDelay;
        _appLifetime = appLifetime;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _listenSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
        _listenSocket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
        _listenSocket.Bind(new IPEndPoint(IPAddress.IPv6Any, _options.ListenPort));
        _listenSocket.Listen(backlog: 512);

        _logger.LogInformation(
            "TCP NIC listener bound to [::]:{Port} (wildcard). Virtual meter addresses are expected from prefix {Prefix}; " +
            "until the host-level local route for that prefix is in place, only loopback connections will actually reach this socket.",
            _options.ListenPort, _options.AddressPrefix);

        using CancellationTokenRegistration shutdownRegistration = _appLifetime.ApplicationStopping.Register(BeginDrain);

        Task idleSweepTask = RunIdleSweepAsync(stoppingToken);
        Task metricsReporterTask = RunMetricsReporterAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            Socket connection;
            try
            {
                connection = await _listenSocket.AcceptAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            _connectionHandlerTasks.Add(HandleConnectionAsync(connection));
        }

        _logger.LogInformation("Accept loop stopped. Waiting for {Count} in-flight session(s) to finish...", _registry.ActiveCount);
        await Task.WhenAll(_connectionHandlerTasks.ToArray());
        await idleSweepTask;
        await metricsReporterTask;

        LogMetricsSummary("Final");
    }

    private void BeginDrain()
    {
        _logger.LogInformation(
            "Shutdown requested. {Count} active connection(s); draining for up to {Seconds}s before force-closing.",
            _registry.ActiveCount, _options.ShutdownDrainSeconds);

        _ = DrainAsync();
    }

    private async Task DrainAsync()
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(_options.ShutdownDrainSeconds);
        while (_registry.ActiveCount > 0 && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(200);
        }

        if (_registry.ActiveCount > 0)
        {
            _logger.LogWarning("{Count} connection(s) still active after drain window, force-closing.", _registry.ActiveCount);
        }
        else
        {
            _logger.LogInformation("All sessions finished on their own before the drain window elapsed.");
        }

        _sessionShutdownCts.Cancel();
    }

    private async Task RunIdleSweepAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(_options.IdleSweepIntervalSeconds);
        var idleTimeout = TimeSpan.FromSeconds(_options.IdleTimeoutSeconds);

        try
        {
            while (true)
            {
                await Task.Delay(interval, stoppingToken);

                DateTimeOffset now = DateTimeOffset.UtcNow;
                foreach (ConnectionState state in _registry.Snapshot())
                {
                    if (now - state.LastActivityUtc > idleTimeout)
                    {
                        _logger.LogInformation(
                            "Meter {MeterId}: idle for over {IdleTimeoutSeconds}s, force-closing stale connection",
                            state.MeterId, idleTimeout.TotalSeconds);
                        _metrics.RecordIdleTimeout();
                        state.CancelDueToIdleTimeout();
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task RunMetricsReporterAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(_options.MetricsIntervalSeconds);

        try
        {
            while (true)
            {
                await Task.Delay(interval, stoppingToken);
                LogMetricsSummary("Periodic");
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void LogMetricsSummary(string kind)
    {
        SimulatorMetricsSnapshot snapshot = _metrics.Snapshot(_registry.ActiveCount);
        _logger.LogInformation(
            "{Kind} metrics: active={Active}, accepted={Accepted}, rejectedCollision={RejectedCollision}, " +
            "rejectedMaxConn={RejectedMaxConn}, rejectedBatchNotRunning={RejectedBatchNotRunning}, " +
            "rejectedNoTemplate={RejectedNoTemplate}, idleTimeouts={IdleTimeouts}, exchanges={Exchanges}, " +
            "avgBridgeLatency={AvgLatencyMs}ms, maxBridgeLatency={MaxLatencyMs}ms, " +
            "avgNetworkLatency={AvgNetworkMs}ms, maxNetworkLatency={MaxNetworkMs}ms",
            kind, snapshot.ActiveConnections, snapshot.TotalAccepted, snapshot.TotalRejectedCollision,
            snapshot.TotalRejectedMaxConnections, snapshot.TotalRejectedBatchNotRunning,
            snapshot.TotalRejectedNoTemplate, snapshot.TotalIdleTimeouts, snapshot.TotalExchanges,
            snapshot.AvgBridgeLatency.TotalMilliseconds, snapshot.MaxBridgeLatency.TotalMilliseconds,
            snapshot.AvgNetworkLatency.TotalMilliseconds, snapshot.MaxNetworkLatency.TotalMilliseconds);
    }

    private async Task HandleConnectionAsync(Socket connection)
    {
        using (connection)
        {
            var localEndPoint = (IPEndPoint)connection.LocalEndPoint!;
            var remoteEndPoint = (IPEndPoint)connection.RemoteEndPoint!;
            var meterId = localEndPoint.Address;

            // A meter must belong to a batch AND that batch must have a resolvable template — a
            // meter with no template can't be simulated, so we reject it (this replaces the old
            // permissive behavior where meters not assigned to any batch were accepted).
            MeterBatch? batch = _meterRegistry.GetBatchForAddress(meterId);
            if (batch is null)
            {
                _logger.LogInformation(
                    "Rejected connection for meter {MeterId} from HES {RemoteEndPoint}: not part of any batch (no template)",
                    meterId, remoteEndPoint);
                _metrics.RecordRejectedNoTemplate();
                return;
            }

            if (batch.Status is BatchStatus.NotStarted or BatchStatus.Stopped)
            {
                _logger.LogInformation(
                    "Rejected connection for meter {MeterId} from HES {RemoteEndPoint}: batch is {BatchStatus}",
                    meterId, remoteEndPoint, batch.Status);
                _metrics.RecordRejectedBatchNotRunning();
                return;
            }

            if (!_templateRegistry.TryResolve(batch.TemplateName, out _))
            {
                _logger.LogWarning(
                    "Rejected connection for meter {MeterId} from HES {RemoteEndPoint}: batch template '{Template}' not found",
                    meterId, remoteEndPoint, batch.TemplateName);
                _metrics.RecordRejectedNoTemplate();
                return;
            }

            if (_registry.ActiveCount >= _options.MaxConcurrentConnections)
            {
                _logger.LogWarning(
                    "Rejected connection for meter {MeterId} from HES {RemoteEndPoint}: max concurrent connections ({Max}) reached",
                    meterId, remoteEndPoint, _options.MaxConcurrentConnections);
                _metrics.RecordRejectedMaxConnections();
                return;
            }

            using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(_sessionShutdownCts.Token);
            var state = new ConnectionState { MeterId = meterId, RemoteEndPoint = remoteEndPoint, SessionCts = sessionCts };

            if (!_registry.TryRegister(meterId, state))
            {
                _logger.LogWarning(
                    "Rejected connection for meter {MeterId} from HES {RemoteEndPoint}: a session is already active for this meter",
                    meterId, remoteEndPoint);
                _metrics.RecordRejectedCollision();
                return;
            }

            _metrics.RecordAccepted();
            _logger.LogInformation(
                "Accepted connection for meter {MeterId} (port {Port}) from HES {RemoteEndPoint}",
                meterId, localEndPoint.Port, remoteEndPoint);

            try
            {
                await RunSessionAsync(connection, state);
            }
            finally
            {
                _registry.Unregister(meterId, state);
                _logger.LogInformation("Connection closed for meter {MeterId}", meterId);
            }
        }
    }

    private async Task RunSessionAsync(Socket connection, ConnectionState state)
    {
        await using var stream = new NetworkStream(connection, ownsSocket: false);
        PipeReader reader = PipeReader.Create(stream);
        PipeWriter writer = PipeWriter.Create(stream);
        CancellationToken sessionToken = state.SessionCts.Token;

        int exchangeCount = 0;

        try
        {
            while (true)
            {
                try
                {
                    WpduFrame? frame = await DlmsWpduFramer.ReadFrameAsync(reader, sessionToken);
                    if (frame is null)
                    {
                        break; // client closed cleanly between frames
                    }

                    state.Touch();
                    _logger.LogDebug(
                        "Meter {MeterId}: received frame (srcWPort={Src}, dstWPort={Dst}, {Length} payload bytes)",
                        state.MeterId, frame.SourceWPort, frame.DestinationWPort, frame.Payload.Length);

                    // Simulated wire time so the fleet doesn't answer implausibly fast. Applied
                    // here — NIC has the request, brain has not seen it yet — and deliberately
                    // OUTSIDE the stopwatch below, so bridge latency stays a true measure of the
                    // brain. The delay is reported separately as network latency.
                    int delayMs = _networkDelay.NextDelayMs();
                    if (delayMs > 0)
                    {
                        await Task.Delay(delayMs, sessionToken);
                    }
                    _metrics.RecordNetworkDelay(TimeSpan.FromMilliseconds(delayMs));

                    var bridgeStopwatch = Stopwatch.StartNew();
                    // Hand the brain the COMPLETE frame; it returns a complete wrapper reply
                    // (Gurux owns wrapper build), which we write back verbatim — no re-wrapping.
                    byte[] response = await _bridge.ExchangeAsync(state.MeterId, frame.Raw, sessionToken);
                    bridgeStopwatch.Stop();
                    _metrics.RecordExchange(bridgeStopwatch.Elapsed);

                    if (response.Length > 0)
                    {
                        await writer.WriteAsync(response, sessionToken);
                    }
                    state.Touch();

                    exchangeCount++;
                    _logger.LogDebug(
                        "Meter {MeterId}: exchange {Count} complete (bridge latency {LatencyMs}ms)",
                        state.MeterId, exchangeCount, bridgeStopwatch.Elapsed.TotalMilliseconds);
                }
                catch (OperationCanceledException)
                {
                    if (state.IdleTimedOut)
                    {
                        _logger.LogInformation("Meter {MeterId}: closing connection after idle timeout", state.MeterId);
                    }
                    else
                    {
                        _logger.LogInformation("Meter {MeterId}: session cancelled (service shutting down)", state.MeterId);
                    }

                    break;
                }
                catch (InvalidDataException ex)
                {
                    _logger.LogWarning(ex, "Meter {MeterId}: malformed frame, closing connection", state.MeterId);
                    break;
                }
                catch (SocketException ex)
                {
                    _logger.LogWarning(ex, "Meter {MeterId}: connection error", state.MeterId);
                    break;
                }
            }
        }
        finally
        {
            await reader.CompleteAsync();
            await writer.CompleteAsync();
        }
    }

    public override void Dispose()
    {
        _listenSocket?.Dispose();
        _sessionShutdownCts.Dispose();
        base.Dispose();
    }
}
