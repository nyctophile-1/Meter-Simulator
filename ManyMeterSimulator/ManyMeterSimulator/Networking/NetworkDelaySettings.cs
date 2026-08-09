using Microsoft.Extensions.Options;
using ManyMeterSimulator.Settings;

namespace ManyMeterSimulator.Networking;

/// <summary>
/// The artificial think-time a NIC waits before handing a request to the brain, so a simulated
/// fleet responds at something closer to real-meter speed instead of instantly.
///
/// Global for every batch by design — per-batch delays were not wanted, and one shared value
/// keeps the hot path free of any per-meter lookup.
///
/// Changed live from the BadComm page: the listener reads the current bounds on every exchange,
/// so an update takes effect on the next request with no restart. The chosen value is persisted
/// to the runtime config store, so it also survives a restart or redeploy.
///
/// Both bounds are capped at <see cref="DelayLimits.MaxNetworkDelayMs"/> - see that type for why
/// the ceiling matters to the idle sweep.
/// </summary>
public sealed class NetworkDelaySettings
{
    /// <summary>
    /// Both bounds in one immutable object behind a single volatile reference: readers can never
    /// observe a torn pair (new lower with old upper) mid-update without any locking.
    /// </summary>
    public sealed record Bounds(int LowerMs, int UpperMs);

    private volatile Bounds _bounds;
    private readonly IRuntimeConfigStore _store;

    public NetworkDelaySettings(IOptions<NetworkDelayOptions> options, IRuntimeConfigStore store)
    {
        _store = store;

        // A value the operator set in the UI outranks the deployed default: it is the more recent,
        // more deliberate decision, and re-applying it after every restart would otherwise be
        // manual. With no persisted value, fall back to configuration (0/0 unless a deployment
        // seeds it).
        DelayRange? persisted = store.Current.NetworkDelay;
        int lower = DelayLimits.ClampNetworkDelay(persisted?.LowerMs ?? options.Value.LowerMs);
        int upper = DelayLimits.ClampNetworkDelay(persisted?.UpperMs ?? options.Value.UpperMs);
        _bounds = new Bounds(lower, Math.Max(lower, upper));
    }

    public Bounds Current => _bounds;

    /// <summary>
    /// Applies new bounds. Returns false (and changes nothing) if either value is negative, above
    /// <see cref="DelayLimits.MaxNetworkDelayMs"/>, or the upper bound is below the lower one.
    /// Rejected rather than silently clamped: an operator who typed 20000 should be told, not
    /// quietly given 10000.
    /// </summary>
    public bool TryUpdate(int lowerMs, int upperMs)
    {
        if (lowerMs < 0 || upperMs < 0 || upperMs < lowerMs ||
            lowerMs > DelayLimits.MaxNetworkDelayMs || upperMs > DelayLimits.MaxNetworkDelayMs)
        {
            return false;
        }

        _bounds = new Bounds(lowerMs, upperMs);

        // Write through so the change survives a restart or redeploy. Only this section is
        // touched, so any other setting in the document is left intact.
        _store.Update(doc => doc.NetworkDelay = new DelayRange { LowerMs = lowerMs, UpperMs = upperMs });
        return true;
    }

    /// <summary>
    /// The delay to apply to the next exchange: a fresh random draw in [LowerMs, UpperMs].
    /// Returns 0 when both bounds are 0, which is the no-delay default.
    /// </summary>
    public int NextDelayMs()
    {
        Bounds b = _bounds;
        if (b.UpperMs <= 0)
        {
            return 0;
        }

        // Upper bound is inclusive, hence +1. Random.Shared is thread-safe, so thousands of
        // concurrent sessions can draw without contending on a shared Random instance.
        return b.LowerMs >= b.UpperMs ? b.LowerMs : Random.Shared.Next(b.LowerMs, b.UpperMs + 1);
    }

    /// <summary>
    /// Scales a base network delay by a bad-comm multiplier and enforces the ceiling.
    ///
    /// Three things are happening, all deliberate:
    ///
    /// 1. <c>Math.Max(1, ...)</c> - with the network delay at 0 the multiplier would have nothing
    ///    to act on, so a bad-comm meter would be indistinguishable from a healthy one.
    /// 2. Past the saturation threshold the result is REDRAWN in an 8-12 s band rather than
    ///    clipped to a constant. Clipping collapses the tail of the latency histogram onto a
    ///    single spike, which looks nothing like real timeouts; the band keeps the same mean and
    ///    preserves variance.
    /// 3. A final unconditional clamp. Redundant today, kept so the ceiling is a property of the
    ///    code rather than of the current formula - the idle sweep's safety depends on it.
    /// </summary>
    public static int ApplyImpairment(int baseDelayMs, int multiplier)
    {
        if (multiplier <= 1)
        {
            return Math.Min(baseDelayMs, DelayLimits.AbsoluteMaxMs);
        }

        long raw = Math.Max(1, baseDelayMs) * (long)multiplier;

        int delay = raw <= DelayLimits.SaturationThresholdMs
            ? (int)raw
            : Random.Shared.Next(DelayLimits.SaturationLowerMs, DelayLimits.SaturationUpperMs + 1);

        return Math.Min(delay, DelayLimits.AbsoluteMaxMs);
    }
}
