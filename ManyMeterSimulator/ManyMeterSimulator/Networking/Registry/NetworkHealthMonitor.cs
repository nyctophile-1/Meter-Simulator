using System.Collections.Concurrent;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Networking.Registry;

/// <summary>
/// Keeps a current reachability picture of every registry endpoint, so the Network page can render
/// state without probing anything itself (network_registry.md §7.1).
///
/// <para>
/// For a broker that is IN USE it reports the live <see cref="MqttNicClient"/> status rather than
/// running a probe of its own. That status is the truth the meters actually experience: a separate
/// probe could connect happily while the real client sits in its reconnect backoff, and the page
/// would show green for a fleet that is answering nothing. Idle brokers and all push targets have
/// no live connection to read, so those are probed.
/// </para>
/// </summary>
public sealed class NetworkHealthMonitor : BackgroundService
{
    private readonly NetworkRegistry _registry;
    private readonly EndpointProber _prober;
    private readonly MqttNicListenerService _listener;
    private readonly NetworkHealthOptions _options;
    private readonly ILogger<NetworkHealthMonitor> _logger;
    private readonly ConcurrentDictionary<string, EndpointHealth> _health = new(StringComparer.OrdinalIgnoreCase);

    public NetworkHealthMonitor(
        NetworkRegistry registry,
        EndpointProber prober,
        MqttNicListenerService listener,
        IOptions<NetworkHealthOptions> options,
        ILogger<NetworkHealthMonitor> logger)
    {
        _registry = registry;
        _prober = prober;
        _listener = listener;
        _options = options.Value;
        _logger = logger;
    }

    public int IntervalSeconds => Math.Max(10, _options.IntervalSeconds);

    /// <summary>Last known health of an endpoint. Unknown until first checked.</summary>
    public EndpointHealth For(string key) => _health.GetValueOrDefault(key, EndpointHealth.Unknown);

    /// <summary>Records a result from elsewhere — the add dialog, or a manual "Test now".</summary>
    public void Record(string key, bool ok, string? error) =>
        _health[key] = new EndpointHealth(ok, error, DateTimeOffset.UtcNow);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // A short initial delay so startup probing does not compete with the listener's own first
        // connections — the live status it can read is better evidence than a probe anyway.
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SweepAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                // A monitor that dies takes the page's health display with it, silently.
                _logger.LogWarning(ex, "Network health sweep failed; will retry.");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(IntervalSeconds), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task SweepAsync(CancellationToken cancellationToken)
    {
        foreach (BrokerEndpoint broker in _registry.Brokers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!broker.Enabled)
            {
                // Nothing to say about an endpoint nobody is using on purpose. Probing it anyway
                // would report a healthy broker the operator has deliberately switched off.
                continue;
            }

            IReadOnlyList<(NicType Transport, MqttConnectionStatus Status)> live =
                _listener.StatusesForBroker(broker.Key);
            if (live.Count > 0)
            {
                bool connected = live.All(s => s.Status.IsConnected);
                string? error = live.FirstOrDefault(s => !s.Status.IsConnected).Status.LastError;
                Record(broker.Key, connected, connected ? null : error ?? "connecting…");
                _registry.RecordBrokerReachable(broker.Key, connected);
                continue;
            }

            ProbeResult probe = await _prober.TestBrokerAsync(broker, _options.TimeoutSeconds, cancellationToken);
            Record(broker.Key, probe.Ok, probe.Error);
            _registry.RecordBrokerReachable(broker.Key, probe.Ok);
        }

        foreach (PushTargetEndpoint target in _registry.PushTargets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!target.Enabled)
            {
                continue;
            }

            ProbeResult probe = await _prober.TestPushTargetAsync(target, _options.TimeoutSeconds, cancellationToken);
            Record(target.Key, probe.Ok, probe.Error);
            _registry.RecordPushTargetReachable(target.Key, probe.Ok);
        }
    }
}

/// <summary>
/// Point-in-time health of one endpoint. <see cref="Ok"/> is deliberately nullable: "not checked
/// yet" is a third state, and collapsing it into false would show a brand-new endpoint as broken.
/// </summary>
public readonly record struct EndpointHealth(bool? Ok, string? Error, DateTimeOffset? CheckedUtc)
{
    public static EndpointHealth Unknown => new(null, null, null);
}

public sealed class NetworkHealthOptions
{
    public const string SectionName = "NetworkHealth";

    /// <summary>How often to sweep. Floored at 10s so a typo cannot turn this into a probe storm.</summary>
    public int IntervalSeconds { get; set; } = 60;

    public int TimeoutSeconds { get; set; } = 10;
}
