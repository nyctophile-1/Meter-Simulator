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
/// Changed live from the Setup page: the listener reads the current bounds on every exchange,
/// so an update takes effect on the next request with no restart. Values are held in memory
/// only, so a restart falls back to the configured <see cref="NetworkDelayOptions"/> defaults.
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
        int lower = Math.Max(0, persisted?.LowerMs ?? options.Value.LowerMs);
        int upper = Math.Max(lower, persisted?.UpperMs ?? options.Value.UpperMs);
        _bounds = new Bounds(lower, upper);
    }

    public Bounds Current => _bounds;

    /// <summary>
    /// Applies new bounds. Returns false (and changes nothing) if either value is negative or
    /// the upper bound is below the lower one.
    /// </summary>
    public bool TryUpdate(int lowerMs, int upperMs)
    {
        if (lowerMs < 0 || upperMs < 0 || upperMs < lowerMs)
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
}
