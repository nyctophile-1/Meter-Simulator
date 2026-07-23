namespace ManyMeterSimulator.Networking;

public class TcpOptions
{
    public const string SectionName = "Tcp";

    public int ListenPort { get; set; } = 4059;

    /// <summary>
    /// The IPv6 /64 the simulated meter fleet lives in. **Per-deployment infrastructure value** —
    /// it MUST match the /64 actually routed to this host (e.g. the AWS ENI-assigned prefix plus
    /// `ip -6 route add local &lt;prefix&gt;/64 dev …`). Override it per server via
    /// appsettings.Production.json or the environment variable <c>Tcp__AddressPrefix</c>. The value
    /// below is only a documentation/dev default (a ULA example) and is validated at startup.
    /// </summary>
    public string AddressPrefix { get; set; } = "fd00:6d65:7472::/64";

    /// <summary>A connection with no activity for longer than this is closed by the idle sweep.</summary>
    public int IdleTimeoutSeconds { get; set; } = 120;

    /// <summary>How often the idle sweep checks for stale connections.</summary>
    public int IdleSweepIntervalSeconds { get; set; } = 30;

    /// <summary>New connections are rejected once this many sessions are active.</summary>
    public int MaxConcurrentConnections { get; set; } = 10_000;

    /// <summary>How often a metrics summary line is logged.</summary>
    public int MetricsIntervalSeconds { get; set; } = 15;

    /// <summary>On shutdown, how long to let in-flight sessions finish their current exchange before force-closing them.</summary>
    public int ShutdownDrainSeconds { get; set; } = 10;
}
