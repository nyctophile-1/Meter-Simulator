namespace ManyMeterSimulator.Brain;

/// <summary>
/// Settings for on-demand push (the dashboard "Send Push" button). Bound from the "Push" config
/// section. The push DESTINATION itself is not here — it's typed live into the dashboard's push-IP
/// box — this only carries the fallback port and defaults the operator rarely changes.
/// </summary>
public sealed class PushOptions
{
    public const string SectionName = "Push";

    /// <summary>
    /// TCP port used when the push destination is a bare IP with no ":port". Ignored when the typed
    /// destination already carries a port.
    /// </summary>
    public int DefaultPort { get; set; } = 4059;

    /// <summary>
    /// false → plaintext DataNotification (readable in Wireshark, good for bring-up).
    /// true  → general-glo-ciphering with the meter's keys.
    /// </summary>
    public bool UseCiphering { get; set; } = false;

    /// <summary>
    /// Optional default that pre-fills the dashboard push-IP box. Empty = box starts blank. The box
    /// is always the source of truth; this is only a convenience.
    /// </summary>
    public string DefaultDestination { get; set; } = "";

    /// <summary>
    /// Cap on how many meters push concurrently WITHIN one wave (see <see cref="ChunkSize"/>), so
    /// "Send Push" on a large batch doesn't open tens of thousands of outbound sockets at once. Each
    /// push is a short blocking connect+write.
    /// </summary>
    public int MaxConcurrency { get; set; } = 64;

    /// <summary>
    /// Meters per wave when pushing a batch. At fleet scale (lakhs of meters), even a
    /// MaxConcurrency-throttled push still fires the ENTIRE batch as one burst — nothing paces the
    /// total volume over time. A broker or HES that can absorb 10-20k messages in a few seconds may
    /// not survive all of them landing within the same second. Waves of this size, spaced by
    /// <see cref="ChunkIntervalSeconds"/>, bound the burst regardless of how large the batch is.
    /// int.MaxValue disables waving — the whole batch goes out as one wave (still gated by
    /// MaxConcurrency), which was the only behavior before this setting existed.
    /// </summary>
    public int ChunkSize { get; set; } = 10_000;

    /// <summary>
    /// Pause between push waves (see <see cref="ChunkSize"/>). Not applied after the last wave.
    /// Zero sends every wave back-to-back with no pacing at all.
    /// </summary>
    public int ChunkIntervalSeconds { get; set; } = 5;

    /// <summary>Outgoing push QoS, independent of the pull listener's subscription QoS.</summary>
    public int PublishQos { get; set; } = 2;

    /// <summary>Publish-only MQTT connections per broker/transport, reused for an entire push.</summary>
    public int PublisherCount { get; set; } = 8;

    public int PublishTimeoutSeconds { get; set; } = 10;

    /// <summary>
    /// How long a TCP push waits for the connect before giving up on that meter. Bounded because a
    /// destination that is routed-but-dead otherwise holds the connection slot for the OS default
    /// (tens of seconds), which at fleet scale is indistinguishable from the simulator hanging.
    /// </summary>
    public int ConnectTimeoutSeconds { get; set; } = 5;

    /// <summary>
    /// How long a single payload write may take once connected.
    ///
    /// <para>
    /// This is the deadline that matters when testing HES capacity: a HES which accepts the TCP
    /// connection but stops draining its receive buffer would otherwise block the send forever —
    /// the socket is healthy, it is the far side that stopped reading. Without this, "the HES got
    /// slow" turns into "the simulator hung", which is the wrong diagnosis and loses the test.
    /// </para>
    /// </summary>
    public int SendTimeoutSeconds { get; set; } = 5;

    /// <summary>
    /// TCP push must originate from the METER's own assigned IP, so the HES push server can tell
    /// which meter sent the data — that source address is the only identity a TCP push carries.
    ///
    /// <para>
    /// True (default) → if the meter's own address cannot be used, the push FAILS with the reason.
    /// A push delivered from the sim server's default address is worse than no push: the HES push
    /// server records it against the wrong (or no) meter, and every meter looks identical.
    /// </para>
    ///
    /// <para>
    /// Set false only for bring-up against a listener that does not care who sent the data (e.g.
    /// proving a path end-to-end). It then falls back to the sim server's default source and warns
    /// loudly on every push.
    /// </para>
    /// </summary>
    public bool RequireMeterSourceIp { get; set; } = true;
}
