namespace ManyMeterSimulator.Networking;

/// <summary>
/// Hard bounds on every artificial delay the NIC applies. Central because these values are
/// load-bearing in two unrelated places: the UI validates against them, and the idle sweep is only
/// safe because <see cref="AbsoluteMaxMs"/> sits well below Tcp:IdleTimeoutSeconds.
///
/// Nothing calls Touch() while an exchange is being delayed, so a delayed exchange looks idle for
/// its whole duration. If <see cref="AbsoluteMaxMs"/> ever approaches the idle timeout, the sweep
/// starts reaping connections mid-exchange - raise the timeout in the same change.
/// </summary>
public static class DelayLimits
{
    /// <summary>Largest configurable network delay bound (10 s).</summary>
    public const int MaxNetworkDelayMs = 10_000;

    /// <summary>Largest configurable bad-comm latency multiplier.</summary>
    public const int MaxMultiplier = 100;

    /// <summary>
    /// Above this, the computed bad-comm delay stops being meaningful and is redrawn inside
    /// [<see cref="SaturationLowerMs"/>, <see cref="SaturationUpperMs"/>].
    /// </summary>
    public const int SaturationThresholdMs = 10_000;

    /// <summary>
    /// Saturated delays are jittered across this band rather than pinned to a constant: clipping
    /// to a single value collapses the tail of the latency histogram onto one spike, which looks
    /// nothing like real timeouts. The band is centred on the threshold, so the mean is unchanged.
    /// </summary>
    public const int SaturationLowerMs = 8_000;

    public const int SaturationUpperMs = 12_000;

    /// <summary>
    /// No delay may ever exceed this, whatever the arithmetic produces. Redundant today (the
    /// saturation band already tops out here) and kept deliberately, so the ceiling is a property
    /// of the code rather than of the current formula.
    /// </summary>
    public const int AbsoluteMaxMs = 12_000;

    /// <summary>Clamps a configurable network-delay bound into range.</summary>
    public static int ClampNetworkDelay(int ms) => Math.Clamp(ms, 0, MaxNetworkDelayMs);

    /// <summary>Clamps a configurable multiplier into range.</summary>
    public static int ClampMultiplier(int multiplier) => Math.Clamp(multiplier, 1, MaxMultiplier);
}
