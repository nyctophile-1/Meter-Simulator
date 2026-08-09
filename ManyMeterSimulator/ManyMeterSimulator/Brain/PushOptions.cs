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
    /// Cap on how many meters push concurrently, so "Send Push" on a large batch doesn't open tens
    /// of thousands of outbound sockets at once. Each push is a short blocking connect+write.
    /// </summary>
    public int MaxConcurrency { get; set; } = 64;

    /// <summary>QoS for MQTT push publishes. HES clamps its own subscribe QoS to 2, so 2 is safe.</summary>
    public int PublishQos { get; set; } = 2;
}
