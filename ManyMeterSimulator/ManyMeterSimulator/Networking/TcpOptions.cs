namespace ManyMeterSimulator.Networking;

public class TcpOptions
{
    public const string SectionName = "Tcp";

    public int ListenPort { get; set; } = 4059;

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
