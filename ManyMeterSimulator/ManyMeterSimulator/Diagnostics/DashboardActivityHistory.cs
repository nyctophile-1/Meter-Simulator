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
        lock (_gate)
        {
            return _samples.ToArray();
        }
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
            byNic[nic] = new NicActivityTotals(snapshot.TotalExchanges, snapshot.TotalAccepted,
                snapshot.TotalPushPayloadsSent, snapshot.TotalSuccessfulCommands);
        }

        SimulatorMetricsSnapshot total = _metrics.Snapshot(_connections.ActiveCount);
        var sample = new DashboardActivitySample(DateTimeOffset.UtcNow, total.ActiveConnections,
            total.TotalExchanges, total.TotalAccepted, byNic, total.TotalSuccessfulCommands);

        lock (_gate)
        {
            _samples.Add(sample);
            if (_samples.Count > MaxPoints)
            {
                _samples.RemoveAt(0);
            }
        }
    }

    public static double PerSecond(IReadOnlyList<DashboardActivitySample> samples,
        Func<DashboardActivitySample, long> total)
    {
        if (samples.Count < 2)
        {
            return 0;
        }

        DashboardActivitySample last = samples[^1];
        DateTimeOffset start = last.TimestampUtc.AddMinutes(-1);
        DashboardActivitySample first = samples.LastOrDefault(s => s.TimestampUtc <= start) ?? samples[0];
        double seconds = (last.TimestampUtc - first.TimestampUtc).TotalSeconds;

        return seconds <= 0 ? 0 : Math.Max(0, (total(last) - total(first)) / seconds);
    }
}

public sealed record DashboardActivitySample(DateTimeOffset TimestampUtc, int ActiveConnections,
    long TotalExchanges, long TotalAccepted, IReadOnlyDictionary<NicType, NicActivityTotals> ByNic,
    long TotalSuccessfulCommands = 0);

public readonly record struct NicActivityTotals(long TotalExchanges, long TotalAccepted,
    long TotalPushPayloadsSent = 0, long TotalSuccessfulCommands = 0);
