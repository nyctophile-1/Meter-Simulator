namespace ManyMeterSimulator.Provisioning;

public enum BatchStatus
{
    /// <summary>Reserved (IP + meter-number range allocated) but not yet accepting connections.</summary>
    NotStarted,

    /// <summary>Active - meters in this batch accept connections.</summary>
    Running,

    /// <summary>Explicitly stopped - new connections to meters in this batch are rejected.</summary>
    Stopped,
}
