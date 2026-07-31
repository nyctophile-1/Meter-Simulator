using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Diagnostics;

/// <summary>
/// Simple in-memory counters for observability - no external metrics infra, just numbers to log.
///
/// Counters are kept per NIC and summed on demand, so "the fleet is fine but Wirepas is rejecting
/// everything" is visible rather than averaged away. The array is indexed by <see cref="NicType"/>,
/// which is dense and small, so recording stays a single interlocked increment on the hot path.
/// </summary>
public sealed class SimulatorMetrics
{
    private static readonly NicType[] AllNics = Enum.GetValues<NicType>();

    private readonly NicCounters[] _byNic;

    public SimulatorMetrics()
    {
        _byNic = new NicCounters[AllNics.Length];
        for (int i = 0; i < _byNic.Length; i++)
        {
            _byNic[i] = new NicCounters();
        }
    }

    public void RecordAccepted(NicType nic) => Interlocked.Increment(ref For(nic).TotalAccepted);

    public void RecordRejectedCollision(NicType nic) => Interlocked.Increment(ref For(nic).TotalRejectedCollision);

    public void RecordRejectedMaxConnections(NicType nic) => Interlocked.Increment(ref For(nic).TotalRejectedMaxConnections);

    public void RecordRejectedBatchNotRunning(NicType nic) => Interlocked.Increment(ref For(nic).TotalRejectedBatchNotRunning);

    public void RecordRejectedNoTemplate(NicType nic) => Interlocked.Increment(ref For(nic).TotalRejectedNoTemplate);

    public void RecordIdleTimeout(NicType nic) => Interlocked.Increment(ref For(nic).TotalIdleTimeouts);

    /// <summary>A message discarded because that meter's mailbox was full — deliberate back-pressure.</summary>
    public void RecordDroppedMailboxFull(NicType nic) => Interlocked.Increment(ref For(nic).TotalDroppedMailboxFull);

    /// <summary>
    /// A structurally broken message — one we recognised as ours but could not unwrap. On a healthy
    /// system this stays at zero, so it is the counter to alarm on.
    /// </summary>
    public void RecordMalformedPacket(NicType nic) => Interlocked.Increment(ref For(nic).TotalMalformedPackets);

    /// <summary>
    /// A message on our topics that is not addressed to a meter we simulate — Wirepas OTAP
    /// broadcasts, or any variant whose decoder does not exist yet.
    ///
    /// Deliberately separate from <see cref="RecordMalformedPacket"/>: this is expected background
    /// traffic and runs to hundreds per hour, so folding it into "malformed" would bury a genuine
    /// decoding regression in noise that looks identical.
    /// </summary>
    public void RecordIgnoredPacket(NicType nic) => Interlocked.Increment(ref For(nic).TotalIgnoredPackets);

    /// <summary>A fragment set abandoned because the rest never arrived.</summary>
    public void RecordFragmentTimeout(NicType nic) => Interlocked.Increment(ref For(nic).TotalFragmentTimeouts);

    public void RecordExchange(NicType nic, TimeSpan bridgeLatency)
    {
        NicCounters c = For(nic);
        Interlocked.Increment(ref c.TotalExchanges);
        Interlocked.Add(ref c.BridgeLatencyTicksSum, bridgeLatency.Ticks);
        InterlockedMax(ref c.BridgeLatencyMaxTicks, bridgeLatency.Ticks);
    }

    /// <summary>Fleet-wide totals across every NIC.</summary>
    public SimulatorMetricsSnapshot Snapshot(int activeConnections)
    {
        long accepted = 0, collision = 0, maxConn = 0, notRunning = 0, noTemplate = 0;
        long idle = 0, exchanges = 0, ticksSum = 0, ticksMax = 0;
        long mailboxFull = 0, malformed = 0, fragTimeouts = 0, ignored = 0;

        foreach (NicCounters c in _byNic)
        {
            accepted += Interlocked.Read(ref c.TotalAccepted);
            collision += Interlocked.Read(ref c.TotalRejectedCollision);
            maxConn += Interlocked.Read(ref c.TotalRejectedMaxConnections);
            notRunning += Interlocked.Read(ref c.TotalRejectedBatchNotRunning);
            noTemplate += Interlocked.Read(ref c.TotalRejectedNoTemplate);
            idle += Interlocked.Read(ref c.TotalIdleTimeouts);
            exchanges += Interlocked.Read(ref c.TotalExchanges);
            ticksSum += Interlocked.Read(ref c.BridgeLatencyTicksSum);
            ticksMax = Math.Max(ticksMax, Interlocked.Read(ref c.BridgeLatencyMaxTicks));
            mailboxFull += Interlocked.Read(ref c.TotalDroppedMailboxFull);
            malformed += Interlocked.Read(ref c.TotalMalformedPackets);
            fragTimeouts += Interlocked.Read(ref c.TotalFragmentTimeouts);
            ignored += Interlocked.Read(ref c.TotalIgnoredPackets);
        }

        return Build(activeConnections, accepted, collision, maxConn, notRunning, noTemplate, idle,
            exchanges, ticksSum, ticksMax, mailboxFull, malformed, fragTimeouts, ignored);
    }

    /// <summary>Totals for a single NIC. <paramref name="activeConnections"/> is the caller's own count.</summary>
    public SimulatorMetricsSnapshot Snapshot(NicType nic, int activeConnections)
    {
        NicCounters c = For(nic);
        return Build(
            activeConnections,
            Interlocked.Read(ref c.TotalAccepted),
            Interlocked.Read(ref c.TotalRejectedCollision),
            Interlocked.Read(ref c.TotalRejectedMaxConnections),
            Interlocked.Read(ref c.TotalRejectedBatchNotRunning),
            Interlocked.Read(ref c.TotalRejectedNoTemplate),
            Interlocked.Read(ref c.TotalIdleTimeouts),
            Interlocked.Read(ref c.TotalExchanges),
            Interlocked.Read(ref c.BridgeLatencyTicksSum),
            Interlocked.Read(ref c.BridgeLatencyMaxTicks),
            Interlocked.Read(ref c.TotalDroppedMailboxFull),
            Interlocked.Read(ref c.TotalMalformedPackets),
            Interlocked.Read(ref c.TotalFragmentTimeouts),
            Interlocked.Read(ref c.TotalIgnoredPackets));
    }

    /// <summary>Every NIC that has seen any traffic at all — what the periodic summary iterates.</summary>
    public IEnumerable<NicType> ActiveNics()
    {
        foreach (NicType nic in AllNics)
        {
            NicCounters c = For(nic);
            if (Interlocked.Read(ref c.TotalAccepted) > 0 ||
                Interlocked.Read(ref c.TotalExchanges) > 0 ||
                Interlocked.Read(ref c.TotalRejectedCollision) > 0 ||
                Interlocked.Read(ref c.TotalRejectedMaxConnections) > 0 ||
                Interlocked.Read(ref c.TotalRejectedBatchNotRunning) > 0 ||
                Interlocked.Read(ref c.TotalRejectedNoTemplate) > 0 ||
                Interlocked.Read(ref c.TotalDroppedMailboxFull) > 0 ||
                Interlocked.Read(ref c.TotalMalformedPackets) > 0 ||
                Interlocked.Read(ref c.TotalIgnoredPackets) > 0)
            {
                yield return nic;
            }
        }
    }

    private static SimulatorMetricsSnapshot Build(
        int activeConnections, long accepted, long collision, long maxConn, long notRunning,
        long noTemplate, long idle, long exchanges, long ticksSum, long ticksMax,
        long mailboxFull, long malformed, long fragmentTimeouts, long ignored)
    {
        TimeSpan avgLatency = exchanges == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(ticksSum / exchanges);

        return new SimulatorMetricsSnapshot(
            activeConnections, accepted, collision, maxConn, notRunning, noTemplate,
            idle, exchanges, avgLatency, TimeSpan.FromTicks(ticksMax),
            mailboxFull, malformed, fragmentTimeouts, ignored);
    }

    private NicCounters For(NicType nic) => _byNic[(int)nic];

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

    // A class (not a struct) with public fields: `ref` interlocked access needs addressable storage,
    // and boxing a struct out of the array would defeat the point.
    private sealed class NicCounters
    {
        public long TotalAccepted;
        public long TotalRejectedCollision;
        public long TotalRejectedMaxConnections;
        public long TotalRejectedBatchNotRunning;
        public long TotalRejectedNoTemplate;
        public long TotalIdleTimeouts;
        public long TotalExchanges;
        public long BridgeLatencyTicksSum;
        public long BridgeLatencyMaxTicks;
        public long TotalDroppedMailboxFull;
        public long TotalMalformedPackets;
        public long TotalIgnoredPackets;
        public long TotalFragmentTimeouts;
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
    long TotalDroppedMailboxFull,
    long TotalMalformedPackets,
    long TotalFragmentTimeouts,
    long TotalIgnoredPackets)
{
    /// <summary>
    /// Exchanges per admitted session. This is the number that says whether callers got PAST the
    /// handshake: ~1 means every session died right after the association, which is invisible in
    /// the raw totals — 70 exchanges across 14 meters reads as healthy until you divide.
    /// </summary>
    public double AvgExchangesPerSession => TotalAccepted == 0 ? 0 : (double)TotalExchanges / TotalAccepted;
}
