using ManyMeterSimulator.BadComm;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// The classifier is the part of BadComm that fails SILENTLY. An unstable hash or a skewed
/// distribution produces a fleet that looks fine and misbehaves weeks later, so these properties
/// are asserted rather than assumed.
/// </summary>
public class MeterClassifierTests
{
    private const int Sample = 200_000;

    private static BadCommConfig Config(double nonComm, double badComm, int seed = 1) => new()
    {
        Enabled = true,
        Seed = seed,
        Auto = new AutoAllocation { NonCommPercent = nonComm, BadCommPercent = badComm },
    };

    [Fact]
    public void Classify_IsDeterministic_ForTheSameIndex()
    {
        var a = new MeterClassifier(Config(0.1, 5.0), 1);
        var b = new MeterClassifier(Config(0.1, 5.0), 99);   // different generation, same inputs

        for (long i = 1; i <= 10_000; i++)
        {
            Assert.Equal(a.Classify(i).Class, b.Classify(i).Class);
        }
    }

    [Fact]
    public void Classify_DistributionIsWithinTolerance()
    {
        var c = new MeterClassifier(Config(1.0, 10.0), 1);

        int nonComm = 0, badComm = 0;
        for (long i = 1; i <= Sample; i++)
        {
            switch (c.Classify(i).Class)
            {
                case CommClass.NonComm: nonComm++; break;
                case CommClass.BadComm: badComm++; break;
            }
        }

        Assert.InRange(nonComm / (double)Sample * 100, 0.85, 1.15);
        Assert.InRange(badComm / (double)Sample * 100, 9.0, 11.0);
    }

    /// <summary>
    /// The "stays impaired" guarantee. Raising a percentage must only ever ADD meters - a meter
    /// that was non-comm cannot become healthy just because the population grew. This is what the
    /// shared-hash-with-cumulative-thresholds design buys, and it silently breaks if someone
    /// later splits the bands across two hash streams.
    /// </summary>
    [Fact]
    public void RaisingNonComm_NeverReleasesAnAlreadyAffectedMeter()
    {
        var before = new MeterClassifier(Config(1.0, 5.0), 1);
        var after = new MeterClassifier(Config(3.0, 5.0), 2);

        for (long i = 1; i <= Sample; i++)
        {
            if (before.Classify(i).Class == CommClass.NonComm)
            {
                Assert.Equal(CommClass.NonComm, after.Classify(i).Class);
            }
        }
    }

    [Fact]
    public void RaisingBadComm_NeverReleasesAnImpairedMeter()
    {
        var before = new MeterClassifier(Config(0.1, 5.0), 1);
        var after = new MeterClassifier(Config(0.1, 20.0), 2);

        for (long i = 1; i <= Sample; i++)
        {
            if (before.Classify(i).Class != CommClass.Healthy)
            {
                Assert.NotEqual(CommClass.Healthy, after.Classify(i).Class);
            }
        }
    }

    [Fact]
    public void DifferentSeed_ReshufflesThePopulation()
    {
        var a = new MeterClassifier(Config(0.1, 5.0, seed: 1), 1);
        var b = new MeterClassifier(Config(0.1, 5.0, seed: 2), 2);

        int differences = 0;
        for (long i = 1; i <= 20_000; i++)
        {
            if (a.Classify(i).Class != b.Classify(i).Class)
            {
                differences++;
            }
        }

        Assert.True(differences > 100, $"Seed change barely moved anything ({differences} differences).");
    }

    [Fact]
    public void Disabled_MakesEveryMeterHealthy()
    {
        var c = new MeterClassifier(new BadCommConfig { Enabled = false, Auto = new AutoAllocation { NonCommPercent = 50, BadCommPercent = 50 } }, 1);

        for (long i = 1; i <= 5_000; i++)
        {
            Assert.Equal(CommClass.Healthy, c.Classify(i).Class);
        }
    }

    [Fact]
    public void Multiplier_IsStablePerMeter()
    {
        var config = Config(0, 100);
        config.Defaults.MultiplierMin = 10;
        config.Defaults.MultiplierMax = 60;
        var c = new MeterClassifier(config, 1);

        for (long i = 1; i <= 5_000; i++)
        {
            MeterImpairment first = c.Classify(i);
            Assert.Equal(first.Multiplier, c.Classify(i).Multiplier);
            Assert.InRange(first.Multiplier, 10, 60);
        }
    }

    /// <summary>Severity must not correlate with band position - see the two-salt note in StableHash.</summary>
    [Fact]
    public void Multiplier_SpansItsRange_NotJustTheEdges()
    {
        var config = Config(0, 100);
        config.Defaults.MultiplierMin = 1;
        config.Defaults.MultiplierMax = 100;
        var c = new MeterClassifier(config, 1);

        var seen = new HashSet<int>();
        for (long i = 1; i <= 20_000; i++)
        {
            seen.Add(c.Classify(i).Multiplier);
        }

        Assert.True(seen.Count > 90, $"Multiplier only produced {seen.Count} distinct values across 1-100.");
    }

    [Fact]
    public void Rules_BeatAutoAllocation()
    {
        BadCommConfig config = Config(100, 0);   // everything would be non-comm
        config.Rules.Add(new BadCommRule
        {
            Id = 1,
            Name = "exempt",
            Order = 1,
            Match = MatchKind.Range,
            From = 10,
            To = 20,
            Effect = CommClass.Healthy,
        });

        var c = new MeterClassifier(config, 1);

        Assert.Equal(CommClass.Healthy, c.Classify(15).Class);
        Assert.Equal(CommClass.NonComm, c.Classify(21).Class);
    }

    [Fact]
    public void Rules_FirstMatchWinsByOrder()
    {
        BadCommConfig config = Config(0, 0);
        config.Rules.Add(new BadCommRule { Id = 2, Name = "second", Order = 2, Match = MatchKind.Range, From = 1, To = 100, Effect = CommClass.NonComm });
        config.Rules.Add(new BadCommRule { Id = 1, Name = "first", Order = 1, Match = MatchKind.Range, From = 1, To = 100, Effect = CommClass.Healthy });

        var c = new MeterClassifier(config, 1);

        Assert.Equal(CommClass.Healthy, c.Classify(50).Class);
    }

    [Fact]
    public void Rules_DisabledAreIgnored()
    {
        BadCommConfig config = Config(0, 0);
        config.Rules.Add(new BadCommRule { Id = 1, Name = "off", Enabled = false, Match = MatchKind.Range, From = 1, To = 100, Effect = CommClass.NonComm });

        var c = new MeterClassifier(config, 1);

        Assert.Equal(CommClass.Healthy, c.Classify(50).Class);
    }

    [Fact]
    public void Rules_ModuloAndListMatch()
    {
        BadCommConfig config = Config(0, 0);
        config.Rules.Add(new BadCommRule { Id = 1, Name = "every 10th", Order = 1, Match = MatchKind.Modulo, Modulus = 10, Remainder = 0, Effect = CommClass.NonComm });
        config.Rules.Add(new BadCommRule { Id = 2, Name = "listed", Order = 2, Match = MatchKind.List, Indices = new List<long> { 7, 13 }, Effect = CommClass.NonComm });

        var c = new MeterClassifier(config, 1);

        Assert.Equal(CommClass.NonComm, c.Classify(50).Class);
        Assert.Equal(CommClass.NonComm, c.Classify(13).Class);
        Assert.Equal(CommClass.Healthy, c.Classify(11).Class);
    }

    /// <summary>fr = 100% is non-comm by behaviour; no special case should be needed anywhere.</summary>
    [Fact]
    public void FailureRate100_IsEquivalentToNonComm()
    {
        BadCommConfig config = Config(0, 0);
        config.Rules.Add(new BadCommRule
        {
            Id = 1, Name = "dead", Match = MatchKind.Range, From = 1, To = 10,
            Effect = CommClass.BadComm, FailureRatePercent = 100,
        });

        var c = new MeterClassifier(config, 1);

        Assert.Equal(100, c.Classify(5).FailureRatePercent);
    }
}
