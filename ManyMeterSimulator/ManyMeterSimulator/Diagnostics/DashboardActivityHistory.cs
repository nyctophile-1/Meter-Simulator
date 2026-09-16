using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Diagnostics;

/// <summary>
/// Continuously captures the dashboard's short-term telemetry. Keeping this hosted rather than
/// inside the page means the graph already has useful context when an operator navigates to it.
/// </summary>
public sealed class DashboardActivityHistory : BackgroundService
{
    public const int SampleIntervalSeconds = 2;
    public const int WindowSeconds = 120;
    private const int MaxPoints = WindowSeconds / SampleIntervalSeconds;

    private static readonly NicType[] AllNics = Enum.GetValues<NicType>();
    private readonly object _gate = new();
    private readonly SimulatorMetrics _metrics;
    private readonly SessionRegistry _connections;
    private readonly List<DashboardActivitySample> _samples = new();

    public DashboardActivityHistory(SimulatorMetrics metrics, SessionRegistry connections)
    {
        _metrics = metrics;
        _connections = connections;
    }

    public IReadOnlyList<DashboardActivitySample> Snapshot()
    {
        lock (_gate) return _samples.ToArray();
    }

    public static double PushesPerSecond(IReadOnlyList<DashboardActivitySample> samples, NicType nic)
    {
        if (samples.Count < 2) return 0;
        var last = samples[^1];
        var first = samples[^2];
        double seconds = (last.TimestampUtc - first.TimestampUtc).TotalSeconds;
        if (seconds <= 0 || !last.ByNic.TryGetValue(nic, out var end)
            || !first.ByNic.TryGetValue(nic, out var start)) return 0;
        return Math.Max(0, (end.TotalPushPayloadsSent - start.TotalPushPayloadsSent) / seconds);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Capture();
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(SampleIntervalSeconds));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken)) Capture();
        }
        catch (OperationCanceledException) { }
    }

    internal void Capture()
    {
        var byNic = new Dictionary<NicType, NicActivityTotals>();
        foreach (NicType nic in AllNics)
        {
            SimulatorMetricsSnapshot snapshot = _metrics.Snapshot(nic, _connections.ActiveCountFor(nic));
            byNic[nic] = new NicActivityTotals(snapshot.TotalExchanges, snapshot.TotalAccepted, snapshot.TotalPushPayloadsSent);
        }

        SimulatorMetricsSnapshot total = _metrics.Snapshot(_connections.ActiveCount);
        var sample = new DashboardActivitySample(DateTimeOffset.UtcNow, total.ActiveConnections,
            total.TotalExchanges, total.TotalAccepted, byNic);
        lock (_gate)
        {
            _samples.Add(sample);
            if (_samples.Count > MaxPoints) _samples.RemoveAt(0);
        }
    }
}

public sealed record DashboardActivitySample(DateTimeOffset TimestampUtc, int ActiveConnections,
    long TotalExchanges, long TotalAccepted, IReadOnlyDictionary<NicType, NicActivityTotals> ByNic);

public readonly record struct NicActivityTotals(long TotalExchanges, long TotalAccepted, long TotalPushPayloadsSent = 0);
