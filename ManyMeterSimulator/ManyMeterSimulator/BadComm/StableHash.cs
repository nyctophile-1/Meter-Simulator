namespace ManyMeterSimulator.BadComm;

/// <summary>
/// SplitMix64 finalizer - a deterministic, well-distributed mix of a 64-bit value.
///
/// Deliberately NOT <see cref="object.GetHashCode"/>: that is randomised per process, so the set
/// of impaired meters would silently reshuffle on every restart. Impairment assignment must be
/// reproducible forever, across restarts, redeploys and machines, because it is computed on demand
/// rather than stored.
/// </summary>
public static class StableHash
{
    /// <summary>Mixes <paramref name="value"/> with <paramref name="salt"/> into a uniform ulong.</summary>
    public static ulong Mix(ulong salt, ulong value)
    {
        // Salt is folded in first so two streams over the same meter index (band selection vs
        // severity) are uncorrelated. Sharing one stream would make severity a function of
        // position within the band - every meter near the edge would be the slowest.
        ulong x = value + 0x9E3779B97F4A7C15UL * (salt + 1);
        x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9UL;
        x = (x ^ (x >> 27)) * 0x94D049BB133111EBUL;
        return x ^ (x >> 31);
    }

    /// <summary>
    /// Uniform value in [0, <paramref name="modulus"/>). Uses the high bits via a widening
    /// multiply (Lemire) rather than <c>%</c>, which would bias the low end.
    /// </summary>
    public static uint ToRange(ulong hash, uint modulus) =>
        modulus == 0 ? 0 : (uint)(((UInt128)hash * modulus) >> 64);
}
