using ManyMeterSimulator.Networking.Nic;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Diagnostics;

/// <summary>
/// Periodic housekeeping over every live session, whatever NIC it arrived on: reap sessions that
/// have gone quiet, and log a metrics summary.
///
/// Both loops used to run inside TcpNicListenerService. Neither was ever TCP-specific — the sweep
/// works on <see cref="ConnectionState"/> via <see cref="SessionRegistry"/> and cancels a token,
/// which the owning NIC interprets however it likes — so hosting them here means every future NIC
/// gets idle reaping and metrics for free instead of copying the loops.
/// </summary>
public sealed class SessionMaintenanceService : BackgroundService
{
    private readonly ILogger<SessionMaintenanceService> _logger;
    private readonly SessionMaintenanceOptions _options;
    private readonly SessionRegistry _sessions;
    private readonly SimulatorMetrics _metrics;

    public SessionMaintenanceService(
        ILogger<SessionMaintenanceService> logger,
        IOptions<SessionMaintenanceOptions> options,
        SessionRegistry sessions,
        SimulatorMetrics metrics)
    {
        _logger = logger;
        _options = options.Value;
        _sessions = sessions;
        _metrics = metrics;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Task sweep = RunIdleSweepAsync(stoppingToken);
        Task reporter = RunMetricsReporterAsync(stoppingToken);

        await Task.WhenAll(sweep, reporter);

        LogMetricsSummary("Final");
    }

    private async Task RunIdleSweepAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(_options.SweepIntervalSeconds);
        var idleTimeout = TimeSpan.FromSeconds(_options.IdleTimeoutSeconds);

        try
        {
            while (true)
            {
                await Task.Delay(interval, stoppingToken);

                DateTimeOffset now = DateTimeOffset.UtcNow;
                foreach (ConnectionState state in _sessions.Snapshot())
                {
                    if (now - state.LastActivityUtc > idleTimeout)
                    {
                        _logger.LogInformation(
                            "Meter {Meter}: idle for over {IdleTimeoutSeconds}s, force-closing stale session",
                            state.Meter, idleTimeout.TotalSeconds);
                        _metrics.RecordIdleTimeout(state.Meter.Nic);
                        state.CancelDueToIdleTimeout();

                        // A TCP session's own loop notices the cancellation and unregisters. A
                        // virtual session has no loop, so reap it here — otherwise it would linger
                        // and permanently block that meter as "already active".
                        if (state.IsVirtual)
                        {
                            _sessions.Unregister(state.Meter, state);
                        }
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
        int active = _sessions.ActiveCount;
        Log(kind, "all", _metrics.Snapshot(active));

        // Only break out per NIC once more than one is actually carrying traffic — on a TCP-only
        // deployment the per-NIC line would just repeat the total.
        NicType[] nics = _metrics.ActiveNics().ToArray();
        if (nics.Length > 1)
        {
            foreach (NicType nic in nics)
            {
                Log(kind, nic.ToString(), _metrics.Snapshot(nic, _sessions.ActiveCountFor(nic)));
            }
        }
    }

    private void Log(string kind, string scope, SimulatorMetricsSnapshot snapshot) =>
        _logger.LogInformation(
            "{Kind} metrics [{Scope}]: active={Active}, accepted={Accepted}, rejectedCollision={RejectedCollision}, " +
            "rejectedMaxConn={RejectedMaxConn}, rejectedBatchNotRunning={RejectedBatchNotRunning}, " +
            "rejectedNoTemplate={RejectedNoTemplate}, idleTimeouts={IdleTimeouts}, exchanges={Exchanges}, " +
            "avgExchangesPerSession={AvgExchanges:F1}, " +
            "avgBridgeLatency={AvgLatencyMs}ms, maxBridgeLatency={MaxLatencyMs}ms, " +
            "droppedMailboxFull={MailboxFull}, malformed={Malformed}, ignored={Ignored}, " +
            "fragmentTimeouts={FragmentTimeouts}",
            kind, scope, snapshot.ActiveConnections, snapshot.TotalAccepted, snapshot.TotalRejectedCollision,
            snapshot.TotalRejectedMaxConnections, snapshot.TotalRejectedBatchNotRunning,
            snapshot.TotalRejectedNoTemplate, snapshot.TotalIdleTimeouts, snapshot.TotalExchanges,
            snapshot.AvgExchangesPerSession,
            snapshot.AvgBridgeLatency.TotalMilliseconds, snapshot.MaxBridgeLatency.TotalMilliseconds,
            snapshot.TotalDroppedMailboxFull, snapshot.TotalMalformedPackets, snapshot.TotalIgnoredPackets,
            snapshot.TotalFragmentTimeouts);
}
