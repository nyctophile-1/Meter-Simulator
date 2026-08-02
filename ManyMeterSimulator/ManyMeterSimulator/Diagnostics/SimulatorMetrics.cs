namespace ManyMeterSimulator.Diagnostics;

/// <summary>Simple in-memory counters for observability - no external metrics infra, just numbers to log.</summary>
public sealed class SimulatorMetrics
{
    private long _totalAccepted;
    private long _totalRejectedCollision;
    private long _totalRejectedMaxConnections;
    private long _totalRejectedBatchNotRunning;
    private long _totalRejectedNoTemplate;
    private long _totalIdleTimeouts;
    private long _totalExchanges;
    private long _bridgeLatencyTicksSum;
    private long _bridgeLatencyMaxTicks;
    // The simulated wire time (NetworkDelaySettings), tracked separately from bridge latency so
    // "how long the brain took" and "how long we pretended the network took" stay distinguishable.
    private long _networkLatencyTicksSum;
    private long _networkLatencyMaxTicks;
    // Bad-comm latency is tracked apart from the network-latency average: a 25x outlier would
    // otherwise drag that figure away from what a healthy meter actually experiences.
    private long _badCommDelayTicksSum;
    private long _badCommDelayCount;
    private long _totalNonCommDrops;
    private long _totalBadCommDrops;

    public void RecordAccepted() => Interlocked.Increment(ref _totalAccepted);

    public void RecordRejectedCollision() => Interlocked.Increment(ref _totalRejectedCollision);

    public void RecordRejectedMaxConnections() => Interlocked.Increment(ref _totalRejectedMaxConnections);

    public void RecordRejectedBatchNotRunning() => Interlocked.Increment(ref _totalRejectedBatchNotRunning);

    public void RecordRejectedNoTemplate() => Interlocked.Increment(ref _totalRejectedNoTemplate);

    public void RecordIdleTimeout() => Interlocked.Increment(ref _totalIdleTimeouts);

    public void RecordExchange(TimeSpan bridgeLatency)
    {
        Interlocked.Increment(ref _totalExchanges);
        Interlocked.Add(ref _bridgeLatencyTicksSum, bridgeLatency.Ticks);
        InterlockedMax(ref _bridgeLatencyMaxTicks, bridgeLatency.Ticks);
    }

    /// <summary>
    /// The simulated network delay actually applied to one exchange. Recorded even when zero, so
    /// the average is over every exchange rather than only the delayed ones - otherwise turning
    /// the delay off would leave a stale average sitting on the dashboard.
    /// </summary>
    public void RecordNetworkDelay(TimeSpan networkLatency)
    {
        Interlocked.Add(ref _networkLatencyTicksSum, networkLatency.Ticks);
        InterlockedMax(ref _networkLatencyMaxTicks, networkLatency.Ticks);
    }

    /// <summary>A request swallowed because the meter is non-comm.</summary>
    public void RecordNonCommDrop() => Interlocked.Increment(ref _totalNonCommDrops);

    /// <summary>An exchange lost to bad-comm packet loss.</summary>
    public void RecordBadCommDrop() => Interlocked.Increment(ref _totalBadCommDrops);

    /// <summary>The (multiplied) delay applied to one bad-comm exchange.</summary>
    public void RecordBadCommDelay(TimeSpan delay)
    {
        Interlocked.Add(ref _badCommDelayTicksSum, delay.Ticks);
        Interlocked.Increment(ref _badCommDelayCount);
    }

    public SimulatorMetricsSnapshot Snapshot(int activeConnections)
    {
        long totalExchanges = Interlocked.Read(ref _totalExchanges);
        long ticksSum = Interlocked.Read(ref _bridgeLatencyTicksSum);
        TimeSpan avgLatency = totalExchanges == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(ticksSum / totalExchanges);

        long netTicksSum = Interlocked.Read(ref _networkLatencyTicksSum);
        TimeSpan avgNetworkLatency = totalExchanges == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(netTicksSum / totalExchanges);

        // Averaged over bad-comm exchanges only, not all exchanges - otherwise the figure would
        // shrink as the healthy population grows and would stop describing a bad meter at all.
        long badCommCount = Interlocked.Read(ref _badCommDelayCount);
        TimeSpan avgBadCommDelay = badCommCount == 0
            ? TimeSpan.Zero
            : TimeSpan.FromTicks(Interlocked.Read(ref _badCommDelayTicksSum) / badCommCount);

        return new SimulatorMetricsSnapshot(
            activeConnections,
            Interlocked.Read(ref _totalAccepted),
            Interlocked.Read(ref _totalRejectedCollision),
            Interlocked.Read(ref _totalRejectedMaxConnections),
            Interlocked.Read(ref _totalRejectedBatchNotRunning),
            Interlocked.Read(ref _totalRejectedNoTemplate),
            Interlocked.Read(ref _totalIdleTimeouts),
            totalExchanges,
            avgLatency,
            TimeSpan.FromTicks(Interlocked.Read(ref _bridgeLatencyMaxTicks)),
            avgNetworkLatency,
            TimeSpan.FromTicks(Interlocked.Read(ref _networkLatencyMaxTicks)),
            Interlocked.Read(ref _totalNonCommDrops),
            Interlocked.Read(ref _totalBadCommDrops),
            avgBadCommDelay);
    }

    private static void InterlockedMax(ref long location, long value)
    {
        long current;
        do
        {
            current = Interlocked.Read(ref location);
            if (value <= current)
            {
                return;
            }
        }
        while (Interlocked.CompareExchange(ref location, value, current) != current);
    }
}

public readonly record struct SimulatorMetricsSnapshot(
    int ActiveConnections,
    long TotalAccepted,
    long TotalRejectedCollision,
    long TotalRejectedMaxConnections,
    long TotalRejectedBatchNotRunning,
    long TotalRejectedNoTemplate,
    long TotalIdleTimeouts,
    long TotalExchanges,
    TimeSpan AvgBridgeLatency,
    TimeSpan MaxBridgeLatency,
    TimeSpan AvgNetworkLatency,
    TimeSpan MaxNetworkLatency,
    long TotalNonCommDrops,
    long TotalBadCommDrops,
    TimeSpan AvgBadCommDelay);
