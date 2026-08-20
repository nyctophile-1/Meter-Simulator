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

    // Admission/exchange counters are per NIC (see NicCounters). The ones below are deliberately
    // FLEET-WIDE: network delay and bad-comm impairment are properties of the simulated link, not
    // of a NIC variant, and today only the TCP listener applies them.

    // The simulated wire time (NetworkDelaySettings), tracked separately from bridge latency so
    // "how long the brain took" and "how long we pretended the network took" stay distinguishable.
    private long _networkLatencyTicksSum;
    private long _networkLatencyMaxTicks;

    // Counted rather than reusing the exchange total, so the average stays well-defined whichever
    // snapshot asks for it — a per-NIC snapshot would otherwise divide a fleet-wide sum by one
    // NIC's exchange count and report a delay nobody experienced.
    private long _networkLatencySamples;

    // Bad-comm latency is tracked apart from the network-latency average: a 25x outlier would
    // otherwise drag that figure away from what a healthy meter actually experiences.
    private long _badCommDelayTicksSum;
    private long _badCommDelayCount;
    private long _totalNonCommDrops;
    private long _totalBadCommDrops;
    // Gauge of decoded inbound requests currently being handled; this is not a session count.
    private long _activeInboundExchanges;

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

    public int ActiveInboundExchanges => (int)Math.Clamp(Interlocked.Read(ref _activeInboundExchanges), 0, int.MaxValue);
    public void BeginInboundExchange() => Interlocked.Increment(ref _activeInboundExchanges);
    public void EndInboundExchange() => Interlocked.Decrement(ref _activeInboundExchanges);

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

    /// <summary>
    /// A request that arrived on a different broker than the meter's batch is bound to. It is still
    /// answered — on the broker it came from, which is what real hardware does — so this is not an
    /// error counter but the evidence that a binding is wrong. Without it a persistent misbinding is
    /// merely survivable and permanently invisible (network_registry.md §5.3).
    /// </summary>
    public void RecordCrossBrokerMessage(NicType nic) => Interlocked.Increment(ref For(nic).TotalCrossBrokerMessages);

    public void RecordExchange(NicType nic, TimeSpan bridgeLatency)
    {
        NicCounters c = For(nic);
        Interlocked.Increment(ref c.TotalExchanges);
        Interlocked.Add(ref c.BridgeLatencyTicksSum, bridgeLatency.Ticks);
        InterlockedMax(ref c.BridgeLatencyMaxTicks, bridgeLatency.Ticks);
    }

    /// <summary>
    /// One meter's push finished. <paramref name="latency"/> covers encode + wire time for that
    /// meter, which is the figure that says whether the HES kept up: it is what stretches when the
    /// far side starts queueing, long before anything actually fails.
    ///
    /// <para>
    /// Recorded per meter rather than per payload so the number lines up with what the UI reports
    /// ("pushed 480/500 meters"), and kept apart from exchange latency because a push is an OUTBOUND
    /// connect the HES never asked for — averaging the two would hide which side is slow.
    /// </para>
    /// </summary>
    public void RecordPushMeter(NicType nic, bool ok, TimeSpan latency)
    {
        NicCounters c = For(nic);
        if (ok)
        {
            Interlocked.Increment(ref c.TotalPushMetersSent);
        }
        else
        {
            Interlocked.Increment(ref c.TotalPushMetersFailed);
        }

        Interlocked.Add(ref c.PushLatencyTicksSum, latency.Ticks);
        Interlocked.Increment(ref c.PushLatencySamples);
        InterlockedMax(ref c.PushLatencyMaxTicks, latency.Ticks);
    }

    /// <summary>
    /// A meter that had nothing to push — no sendable PushSetup. Counted separately because it is
    /// neither a success nor a failure, and folding it into either would make Sent + Failed stop
    /// adding up to the batch size that the operator can see on screen.
    /// </summary>
    public void RecordPushSkipped(NicType nic) => Interlocked.Increment(ref For(nic).TotalPushMetersSkipped);

    /// <summary>
    /// Individual payloads (DataNotification frames) delivered for one meter. A meter can carry
    /// several push objects, so this runs ahead of the meter counts and is what to compare against
    /// what the HES says it received.
    /// </summary>
    public void RecordPushPayloads(NicType nic, int sent, int failed)
    {
        NicCounters c = For(nic);
        if (sent > 0)
        {
            Interlocked.Add(ref c.TotalPushPayloadsSent, sent);
        }

        if (failed > 0)
        {
            Interlocked.Add(ref c.TotalPushPayloadsFailed, failed);
        }
    }

    /// <summary>
    /// The simulated network delay actually applied to one exchange. Recorded even when zero, so
    /// the average is over every exchange rather than only the delayed ones - otherwise turning
    /// the delay off would leave a stale average sitting on the dashboard.
    /// </summary>
    public void RecordNetworkDelay(TimeSpan networkLatency)
    {
        Interlocked.Add(ref _networkLatencyTicksSum, networkLatency.Ticks);
        Interlocked.Increment(ref _networkLatencySamples);
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

    /// <summary>Fleet-wide totals across every NIC.</summary>
    public SimulatorMetricsSnapshot Snapshot(int activeConnections)
    {
        long accepted = 0, collision = 0, maxConn = 0, notRunning = 0, noTemplate = 0;
        long idle = 0, exchanges = 0, ticksSum = 0, ticksMax = 0;
        long mailboxFull = 0, malformed = 0, fragTimeouts = 0, ignored = 0, crossBroker = 0;
        long pushSent = 0, pushFailed = 0, pushSkipped = 0, pushPayloadsSent = 0, pushPayloadsFailed = 0;
        long pushTicksSum = 0, pushTicksMax = 0, pushSamples = 0;

        foreach (NicCounters c in _byNic)
        {
            pushSent += Interlocked.Read(ref c.TotalPushMetersSent);
            pushFailed += Interlocked.Read(ref c.TotalPushMetersFailed);
            pushSkipped += Interlocked.Read(ref c.TotalPushMetersSkipped);
            pushPayloadsSent += Interlocked.Read(ref c.TotalPushPayloadsSent);
            pushPayloadsFailed += Interlocked.Read(ref c.TotalPushPayloadsFailed);
            pushTicksSum += Interlocked.Read(ref c.PushLatencyTicksSum);
            pushSamples += Interlocked.Read(ref c.PushLatencySamples);
            pushTicksMax = Math.Max(pushTicksMax, Interlocked.Read(ref c.PushLatencyMaxTicks));
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
            crossBroker += Interlocked.Read(ref c.TotalCrossBrokerMessages);
        }

        return Build(activeConnections, accepted, collision, maxConn, notRunning, noTemplate, idle,
            exchanges, ticksSum, ticksMax, mailboxFull, malformed, fragTimeouts, ignored, crossBroker,
            pushSent, pushFailed, pushSkipped, pushPayloadsSent, pushPayloadsFailed,
            pushTicksSum, pushTicksMax, pushSamples);
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
            Interlocked.Read(ref c.TotalIgnoredPackets),
            Interlocked.Read(ref c.TotalCrossBrokerMessages),
            Interlocked.Read(ref c.TotalPushMetersSent),
            Interlocked.Read(ref c.TotalPushMetersFailed),
            Interlocked.Read(ref c.TotalPushMetersSkipped),
            Interlocked.Read(ref c.TotalPushPayloadsSent),
            Interlocked.Read(ref c.TotalPushPayloadsFailed),
            Interlocked.Read(ref c.PushLatencyTicksSum),
            Interlocked.Read(ref c.PushLatencyMaxTicks),
            Interlocked.Read(ref c.PushLatencySamples));
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

    // Instance rather than static now: the admission/exchange figures are passed in (per NIC or
    // summed), while the network-delay and bad-comm figures are read from fleet-wide state here.
    private SimulatorMetricsSnapshot Build(
        int activeConnections, long accepted, long collision, long maxConn, long notRunning,
        long noTemplate, long idle, long exchanges, long ticksSum, long ticksMax,
        long mailboxFull, long malformed, long fragmentTimeouts, long ignored, long crossBroker,
        long pushSent, long pushFailed, long pushSkipped, long pushPayloadsSent,
        long pushPayloadsFailed, long pushTicksSum, long pushTicksMax, long pushSamples)
    {
        // Averaged over meters actually pushed (success or failure), not over every meter in the
        // fleet — a batch that never pushed must not drag this toward zero and read as "fast".
        TimeSpan avgPushLatency = pushSamples == 0
            ? TimeSpan.Zero
            : TimeSpan.FromTicks(pushTicksSum / pushSamples);

        TimeSpan avgLatency = exchanges == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(ticksSum / exchanges);

        // Divided by its own sample count, not by `exchanges`, so a per-NIC snapshot cannot divide
        // a fleet-wide sum by one NIC's exchanges and invent a delay nobody saw.
        long netSamples = Interlocked.Read(ref _networkLatencySamples);
        TimeSpan avgNetworkLatency = netSamples == 0
            ? TimeSpan.Zero
            : TimeSpan.FromTicks(Interlocked.Read(ref _networkLatencyTicksSum) / netSamples);

        // Averaged over bad-comm exchanges only, not all exchanges - otherwise the figure would
        // shrink as the healthy population grows and would stop describing a bad meter at all.
        long badCommCount = Interlocked.Read(ref _badCommDelayCount);
        TimeSpan avgBadCommDelay = badCommCount == 0
            ? TimeSpan.Zero
            : TimeSpan.FromTicks(Interlocked.Read(ref _badCommDelayTicksSum) / badCommCount);

        return new SimulatorMetricsSnapshot(
            activeConnections, accepted, collision, maxConn, notRunning, noTemplate,
            idle, exchanges, avgLatency, TimeSpan.FromTicks(ticksMax),
            mailboxFull, malformed, fragmentTimeouts, ignored, crossBroker,
            avgNetworkLatency, TimeSpan.FromTicks(Interlocked.Read(ref _networkLatencyMaxTicks)),
            Interlocked.Read(ref _totalNonCommDrops),
            Interlocked.Read(ref _totalBadCommDrops),
            avgBadCommDelay,
            pushSent, pushFailed, pushSkipped, pushPayloadsSent, pushPayloadsFailed,
            avgPushLatency, TimeSpan.FromTicks(pushTicksMax));
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
        public long TotalCrossBrokerMessages;
        public long TotalPushMetersSent;
        public long TotalPushMetersFailed;
        public long TotalPushMetersSkipped;
        public long TotalPushPayloadsSent;
        public long TotalPushPayloadsFailed;
        public long PushLatencyTicksSum;
        public long PushLatencyMaxTicks;
        public long PushLatencySamples;
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
    long TotalIgnoredPackets,
    /// <summary>Requests answered on a broker other than the one the meter's batch is bound to.</summary>
    long TotalCrossBrokerMessages,
    // Fleet-wide regardless of which NIC this snapshot describes — see SimulatorMetrics.
    TimeSpan AvgNetworkLatency,
    TimeSpan MaxNetworkLatency,
    long TotalNonCommDrops,
    long TotalBadCommDrops,
    TimeSpan AvgBadCommDelay,
    /// <summary>Meters whose push was fully delivered.</summary>
    long TotalPushMetersSent,
    /// <summary>Meters whose push failed, wholly or partly.</summary>
    long TotalPushMetersFailed,
    /// <summary>Meters that had no sendable PushSetup — neither success nor failure.</summary>
    long TotalPushMetersSkipped,
    long TotalPushPayloadsSent,
    long TotalPushPayloadsFailed,
    TimeSpan AvgPushLatency,
    TimeSpan MaxPushLatency)
{
    /// <summary>Meters actually attempted — what Sent and Failed add up to.</summary>
    public long TotalPushMetersAttempted => TotalPushMetersSent + TotalPushMetersFailed;

    /// <summary>
    /// Share of attempted pushes the HES accepted, 0..100. The headline number for "can the HES take
    /// what the fleet sends": it is what falls first when the far side starts shedding load.
    /// </summary>
    public double PushSuccessPercent =>
        TotalPushMetersAttempted == 0 ? 0 : (double)TotalPushMetersSent / TotalPushMetersAttempted * 100;

    /// <summary>
    /// Exchanges per admitted session. This is the number that says whether callers got PAST the
    /// handshake: ~1 means every session died right after the association, which is invisible in
    /// the raw totals — 70 exchanges across 14 meters reads as healthy until you divide.
    /// </summary>
    public double AvgExchangesPerSession => TotalAccepted == 0 ? 0 : (double)TotalExchanges / TotalAccepted;
}
