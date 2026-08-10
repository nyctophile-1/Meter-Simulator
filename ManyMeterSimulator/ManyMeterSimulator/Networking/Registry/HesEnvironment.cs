namespace ManyMeterSimulator.Networking.Registry;

/// <summary>
/// One named HES environment: a paired TCP push listener and MQTT broker that together represent
/// a single HES instance. Either half may be absent (TCP-only for a pure-push fleet, MQTT-only for
/// a pure-RF fleet), but the environment is always a single entity in the registry — no more
/// separate "broker" and "push target" rows that have to be named consistently by hand.
/// </summary>
public sealed class HesEnvironment
{
    public required string Key { get; init; }

    /// <summary>Human-readable display name. Defaults to Key when not set.</summary>
    public string Name { get; set; } = "";

    // ── TCP push endpoint ──────────────────────────────────────────────────────────────────────

    /// <summary>IPv6 address (or LB DNS) of the HES TCP push listener. Empty means not configured.</summary>
    public string TcpHost { get; set; } = "";

    public int TcpPort { get; set; } = 4059;

    // ── MQTT broker endpoint ───────────────────────────────────────────────────────────────────

    /// <summary>Hostname of the MQTT broker. Empty means not configured.</summary>
    public string BrokerHost { get; set; } = "";

    public int BrokerPort { get; set; } = 1883;

    public string BrokerUsername { get; set; } = "";

    /// <summary>
    /// Plaintext in memory, encrypted at rest — see <see cref="ISecretProtector"/>.
    /// Never rendered back to the UI and never logged.
    /// </summary>
    public string BrokerPassword { get; set; } = "";

    public bool BrokerUseTls { get; set; }

    // ── Operational state ──────────────────────────────────────────────────────────────────────

    public bool Enabled { get; set; } = true;

    /// <summary>False for a row added through the "save unverified" escape hatch.</summary>
    public bool Verified { get; set; }

    public DateTimeOffset? LastVerifiedUtc { get; set; }

    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    // ── Capability flags ───────────────────────────────────────────────────────────────────────

    public bool HasTcp => !string.IsNullOrWhiteSpace(TcpHost);

    public bool HasBroker => !string.IsNullOrWhiteSpace(BrokerHost);

    public string DisplayName => string.IsNullOrWhiteSpace(Name) ? Key : Name;

    // ── Adapters for the existing MQTT/push infrastructure ────────────────────────────────────

    /// <summary>
    /// Presents this environment's broker half as a <see cref="BrokerEndpoint"/> so the MQTT
    /// listener, binding planner, and prober work without changes. Only call when
    /// <see cref="HasBroker"/> is true — Host will be empty otherwise and every connect will fail.
    /// </summary>
    internal BrokerEndpoint AsBrokerEndpoint() => new()
    {
        Key = Key,
        Host = BrokerHost,
        Port = BrokerPort,
        Username = BrokerUsername,
        Password = BrokerPassword,
        UseTls = BrokerUseTls,
        Enabled = Enabled,
        Verified = Verified,
        LastVerifiedUtc = LastVerifiedUtc,
        CreatedAtUtc = CreatedAtUtc,
    };

    /// <summary>
    /// Presents this environment's TCP half as a <see cref="PushTargetEndpoint"/> so
    /// <see cref="ManyMeterSimulator.Brain.PushCoordinator"/> and the prober work without changes.
    /// Only call when <see cref="HasTcp"/> is true.
    /// </summary>
    internal PushTargetEndpoint AsPushTargetEndpoint() => new()
    {
        Key = Key,
        Address = TcpHost,
        Port = TcpPort,
        Enabled = Enabled,
        Verified = Verified,
        LastVerifiedUtc = LastVerifiedUtc,
        CreatedAtUtc = CreatedAtUtc,
    };

    public string Describe()
    {
        var parts = new List<string>(2);
        if (HasTcp) parts.Add($"TCP {TcpHost}:{TcpPort}");
        if (HasBroker) parts.Add($"MQTT {BrokerHost}:{BrokerPort}");
        return parts.Count > 0 ? $"{Key} ({string.Join(", ", parts)})" : Key;
    }
}
