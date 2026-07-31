namespace ManyMeterSimulator.Diagnostics;

/// <summary>
/// Housekeeping that applies to sessions on ANY NIC. These used to live on TcpOptions, back when
/// TCP was the only transport and the sweep ran inside the listener; they are transport-independent
/// policy, so they moved out with the sweep itself.
/// </summary>
public class SessionMaintenanceOptions
{
    public const string SectionName = "Sessions";

    /// <summary>
    /// A session with no activity for longer than this is closed by the idle sweep.
    ///
    /// On TCP this force-closes a socket the HES left open. On the connectionless MQTT NICs it is
    /// the ONLY thing that ends a session — there is no close event — so it doubles as the bound on
    /// how long a DLMS association may sit half-open.
    /// </summary>
    public int IdleTimeoutSeconds { get; set; } = 120;

    /// <summary>How often the idle sweep checks for stale sessions.</summary>
    public int SweepIntervalSeconds { get; set; } = 30;

    /// <summary>How often a metrics summary line is logged (per NIC that has seen traffic).</summary>
    public int MetricsIntervalSeconds { get; set; } = 15;
}
