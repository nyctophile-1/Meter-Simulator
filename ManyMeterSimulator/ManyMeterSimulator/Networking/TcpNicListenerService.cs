using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Framing;
using ManyMeterSimulator.MqttBridge;
using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Networking;

/// <summary>
/// The 4G TCP NIC: one wildcard socket serving the whole meter prefix, since the kernel routes every
/// meter address to this host and the socket's LOCAL address identifies the meter.
///
/// Deliberately narrow — accept, identify, deframe, funnel. Admission policy lives in
/// <see cref="MeterAdmission"/> and idle reaping/metrics in <see cref="SessionMaintenanceService"/>,
/// because none of those are TCP concerns; what remains here is only what a byte-stream transport
/// actually has to do.
/// </summary>
public class TcpNicListenerService : BackgroundService
{
    private readonly ILogger<TcpNicListenerService> _logger;
    private readonly TcpOptions _options;
    private readonly SessionRegistry _registry;
    private readonly MeterAdmission _admission;
    private readonly IMeterSimBridge _bridge;
    private readonly SimulatorMetrics _metrics;
    // The meter/template registries are gone from here: admission moved to MeterAdmission
    // (virtual_nics.md Phase B-1). These two stay because they are consulted on the exchange
    // path itself, not at admission time.
    private readonly NetworkDelaySettings _networkDelay;
    private readonly BadCommSettings _badComm;
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
        SessionRegistry registry,
        MeterAdmission admission,
        IMeterSimBridge bridge,
        SimulatorMetrics metrics,
        NetworkDelaySettings networkDelay,
        BadCommSettings badComm,
        IHostApplicationLifetime appLifetime)
    {
        _logger = logger;
        _options = options.Value;
        _registry = registry;
        _admission = admission;
        _bridge = bridge;
        _metrics = metrics;
        _networkDelay = networkDelay;
        _badComm = badComm;
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

    private async Task HandleConnectionAsync(Socket connection)
    {
        using (connection)
        {
            var localEndPoint = (IPEndPoint)connection.LocalEndPoint!;
            var remoteEndPoint = (IPEndPoint)connection.RemoteEndPoint!;
            var meterId = localEndPoint.Address;

            // The kernel routes the whole meter prefix here, so the socket's LOCAL address is the
            // meter's own address and carries its index — the identity everything below uses.
            MeterRef meter = MeterRef.FromTcpAddress(meterId);

            using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(_sessionShutdownCts.Token);
            var state = new ConnectionState
            {
                Meter = meter,
                MeterAddress = meterId,
                RemoteEndPoint = remoteEndPoint,
                SessionCts = sessionCts,
            };

            AdmissionResult admission = _admission.TryAdmit(meter, state, _options.MaxConcurrentConnections);
            if (!admission.IsAdmitted)
            {
                // TCP expresses a refusal by closing the socket; the counters are already recorded.
                _logger.LogInformation(
                    "Rejected connection for meter {MeterId} from HES {RemoteEndPoint}: {Reason}",
                    meterId, remoteEndPoint, admission.Reason);
                return;
            }

            _logger.LogInformation(
                "Accepted connection for meter {MeterId} (port {Port}) from HES {RemoteEndPoint}",
                meterId, localEndPoint.Port, remoteEndPoint);

            try
            {
                await RunSessionAsync(connection, state);
            }
            finally
            {
                _registry.Unregister(meter, state);
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
                        state.MeterAddress, frame.SourceWPort, frame.DestinationWPort, frame.Payload.Length);

                    // Re-resolve if the operator changed the BadComm config since this connection
                    // was classified, so a change is retroactive for open sessions too.
                    MeterClassifier classifier = _badComm.Classifier;
                    if (state.ImpairmentGeneration != classifier.Generation)
                    {
                        // The meter index is carried directly now, so this no longer has to decode
                        // it back out of an IPv6 address (virtual_nics.md §4).
                        state.SetImpairment(
                            classifier.Classify(state.Meter.Index),
                            classifier.Generation);
                    }

                    MeterImpairment impairment = state.Impairment;

                    // Non-comm: swallow the request. No reply, no close - the HES waits out its
                    // own timeout and retries, which is what makes the command consume the full
                    // SLA budget. Closing here instead would fast-fail and understate the cost.
                    if (impairment.Class == CommClass.NonComm)
                    {
                        _metrics.RecordNonCommDrop();
                        _logger.LogDebug("Meter {Meter}: non-comm, request swallowed", state.Meter);
                        continue;
                    }

                    // Simulated wire time so the fleet doesn't answer implausibly fast. Applied
                    // here — NIC has the request, brain has not seen it yet — and deliberately
                    // OUTSIDE the stopwatch below, so bridge latency stays a true measure of the
                    // brain. The delay is reported separately as network latency.
                    int delayMs = NetworkDelaySettings.ApplyImpairment(
                        _networkDelay.NextDelayMs(), impairment.Multiplier);

                    if (delayMs > 0)
                    {
                        await Task.Delay(delayMs, sessionToken);
                    }
                    _metrics.RecordNetworkDelay(TimeSpan.FromMilliseconds(delayMs));

                    // Bad-comm packet loss, drawn per exchange. A command needs ~10 exchanges, so
                    // a 5% drop here fails roughly 40% of commands - the HES must retry.
                    if (impairment.Class == CommClass.BadComm)
                    {
                        _metrics.RecordBadCommDelay(TimeSpan.FromMilliseconds(delayMs));

                        if (impairment.FailureRatePercent > 0 &&
                            Random.Shared.NextDouble() * 100 < impairment.FailureRatePercent)
                        {
                            _metrics.RecordBadCommDrop();
                            _logger.LogDebug("Meter {Meter}: bad-comm dropped this exchange", state.Meter);
                            continue;
                        }
                    }

                    var bridgeStopwatch = Stopwatch.StartNew();
                    // Hand the brain the COMPLETE frame; it returns a complete wrapper reply
                    // (Gurux owns wrapper build), which we write back verbatim — no re-wrapping.
                    byte[] response = await _bridge.ExchangeAsync(state.Meter, frame.Raw, sessionToken);
                    bridgeStopwatch.Stop();
                    _metrics.RecordExchange(state.Meter.Nic, bridgeStopwatch.Elapsed);

                    if (response.Length > 0)
                    {
                        await writer.WriteAsync(response, sessionToken);
                    }
                    state.Touch();

                    exchangeCount++;
                    _logger.LogDebug(
                        "Meter {MeterId}: exchange {Count} complete (bridge latency {LatencyMs}ms)",
                        state.MeterAddress, exchangeCount, bridgeStopwatch.Elapsed.TotalMilliseconds);
                }
                catch (OperationCanceledException)
                {
                    if (state.IdleTimedOut)
                    {
                        _logger.LogInformation("Meter {MeterId}: closing connection after idle timeout", state.MeterAddress);
                    }
                    else
                    {
                        _logger.LogInformation("Meter {MeterId}: session cancelled (service shutting down)", state.MeterAddress);
                    }

                    break;
                }
                catch (InvalidDataException ex)
                {
                    _logger.LogWarning(ex, "Meter {MeterId}: malformed frame, closing connection", state.MeterAddress);
                    break;
                }
                catch (SocketException ex)
                {
                    _logger.LogWarning(ex, "Meter {MeterId}: connection error", state.MeterAddress);
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
