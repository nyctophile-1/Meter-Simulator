using ManyMeterSimulator.Networking;
using Xunit;

namespace ManyMeterSimulator.Tests;

public class NetworkDelayTests
{
    /// <summary>
    /// The ceiling is what makes the idle sweep safe: nothing calls Touch() during a delay, so a
    /// delay approaching Tcp:IdleTimeoutSeconds would get connections reaped mid-exchange. Swept
    /// across the whole configurable input space rather than spot-checked.
    /// </summary>
    [Fact]
    public void ApplyImpairment_NeverExceedsTheAbsoluteCeiling()
    {
        int[] baseDelays = { 0, 1, 50, 100, 300, 1_000, 5_000, DelayLimits.MaxNetworkDelayMs };

        foreach (int baseMs in baseDelays)
        {
            for (int mult = 1; mult <= DelayLimits.MaxMultiplier; mult++)
            {
                for (int draw = 0; draw < 20; draw++)
                {
                    int delay = NetworkDelaySettings.ApplyImpairment(baseMs, mult);
                    Assert.InRange(delay, 0, DelayLimits.AbsoluteMaxMs);
                }
            }
        }
    }

    [Fact]
    public void ApplyImpairment_BelowThreshold_MultipliesExactly()
    {
        Assert.Equal(5_000, NetworkDelaySettings.ApplyImpairment(200, 25));
        Assert.Equal(2_500, NetworkDelaySettings.ApplyImpairment(100, 25));
        Assert.Equal(7_500, NetworkDelaySettings.ApplyImpairment(300, 25));
    }

    /// <summary>Saturated draws must spread across the band, not collapse onto one value.</summary>
    [Fact]
    public void ApplyImpairment_AboveThreshold_JittersAcrossTheBand()
    {
        var seen = new HashSet<int>();
        for (int i = 0; i < 500; i++)
        {
            int delay = NetworkDelaySettings.ApplyImpairment(1_000, 100);   // raw = 100 s
            Assert.InRange(delay, DelayLimits.SaturationLowerMs, DelayLimits.SaturationUpperMs);
            seen.Add(delay);
        }

        Assert.True(seen.Count > 50, $"Saturated delay barely varied ({seen.Count} distinct values).");
    }

    /// <summary>With nd at 0 a multiplier would have nothing to act on, so the base floors at 1 ms.</summary>
    [Fact]
    public void ApplyImpairment_ZeroBase_StillProducesDelayForBadMeters()
    {
        Assert.Equal(25, NetworkDelaySettings.ApplyImpairment(0, 25));
    }

    [Fact]
    public void ApplyImpairment_HealthyMultiplier_LeavesDelayUntouched()
    {
        Assert.Equal(200, NetworkDelaySettings.ApplyImpairment(200, 1));
        Assert.Equal(0, NetworkDelaySettings.ApplyImpairment(0, 1));
    }

    [Fact]
    public void ClampNetworkDelay_BoundsToTenSeconds()
    {
        Assert.Equal(DelayLimits.MaxNetworkDelayMs, DelayLimits.ClampNetworkDelay(999_999));
        Assert.Equal(0, DelayLimits.ClampNetworkDelay(-5));
        Assert.Equal(250, DelayLimits.ClampNetworkDelay(250));
    }
}
