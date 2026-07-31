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

    /// <summary>New connections are rejected once this many sessions are active.</summary>
    public int MaxConcurrentConnections { get; set; } = 10_000;

    // Idle timeout, sweep interval and the metrics interval used to live here. They are not TCP
    // concerns — every NIC's sessions age out the same way — so they moved to
    // <see cref="ManyMeterSimulator.Diagnostics.SessionOptions"/> ("Sessions" config section)
    // along with the sweep itself.

    /// <summary>On shutdown, how long to let in-flight sessions finish their current exchange before force-closing them.</summary>
    public int ShutdownDrainSeconds { get; set; } = 10;
}
