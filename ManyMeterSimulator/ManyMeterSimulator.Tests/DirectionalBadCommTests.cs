using System.Text.Json;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using ManyMeterSimulator.Settings;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public class DirectionalBadCommTests
{
    private static BadCommConfig Offline() => new()
    {
        Enabled = true,
        Seed = 42,
        Auto = new AutoAllocation { NonCommPercent = 100, BadCommPercent = 0 },
    };

    [Theory]
    [InlineData(CommunicationDirection.Pull)]
    [InlineData(CommunicationDirection.Push)]
    public void UpdatingOneDirectionPreservesTheOtherAcrossRestart(CommunicationDirection direction)
    {
        var store = new Store();
        store.Current.BadComm = Offline();
        store.Current.NetworkDelay = new DelayRange { LowerMs = 123, UpperMs = 123 };
        var badComm = new BadCommSettings(store);
        var delay = new NetworkDelaySettings(Options.Create(new NetworkDelayOptions()), store);
        var other = direction == CommunicationDirection.Pull ? CommunicationDirection.Push : CommunicationDirection.Pull;
        var otherClassifier = badComm.GetClassifier(other);

        Assert.True(badComm.TryUpdate(new BadCommConfig { Enabled = false }, out _, direction));
        Assert.True(delay.TryUpdate(7, 7, direction));
        Assert.Same(otherClassifier, badComm.GetClassifier(other));
        Assert.Equal(CommClass.Healthy, badComm.GetClassifier(direction).Classify(1).Class);
        Assert.Equal(CommClass.NonComm, badComm.GetClassifier(other).Classify(1).Class);
        Assert.Equal(7, delay.NextDelayMs(direction));
        Assert.Equal(123, delay.NextDelayMs(other));

        store.Current = JsonSerializer.Deserialize<MayaRuntimeConfig>(JsonSerializer.Serialize(store.Current))!;
        var restarted = new BadCommSettings(store);
        var restartedDelay = new NetworkDelaySettings(Options.Create(new NetworkDelayOptions()), store);
        Assert.Equal(CommClass.Healthy, restarted.GetClassifier(direction).Classify(1).Class);
        Assert.Equal(CommClass.NonComm, restarted.GetClassifier(other).Classify(1).Class);
        Assert.Equal(7, restartedDelay.NextDelayMs(direction));
        Assert.Equal(123, restartedDelay.NextDelayMs(other));
    }

    [Fact]
    public void LegacyConfigIsCopiedWithoutSharingEditableRules()
    {
        var store = new Store();
        store.Current.BadComm = Offline();
        store.Current.BadComm.Rules.Add(new BadCommRule { Name = "exempt", Match = MatchKind.List, Indices = [1], Effect = CommClass.Healthy });
        var settings = new BadCommSettings(store);
        var draft = settings.Snapshot(CommunicationDirection.Push);
        draft.Rules[0].Indices.Add(2);
        Assert.True(settings.TryUpdate(draft, out _, CommunicationDirection.Push));
        Assert.Equal(CommClass.Healthy, settings.GetClassifier(CommunicationDirection.Push).Classify(2).Class);
        Assert.Equal(CommClass.NonComm, settings.Classifier.Classify(2).Class);
        Assert.Single(store.Current.BadComm.Rules[0].Indices);
    }

    [Fact]
    public void ExportImportPreservesDistinctDirections()
    {
        var source = Create();
        source.BadComm.TryUpdate(Offline(), out _, CommunicationDirection.Push);
        source.Delay.TryUpdate(123, 123, CommunicationDirection.Push);
        source.Delay.TryUpdate(7, 7);
        var target = Create();
        target.Bundle.ImportBadComm(source.Bundle.ExportBadComm());
        Assert.Equal(CommClass.NonComm, target.BadComm.GetClassifier(CommunicationDirection.Push).Classify(1).Class);
        Assert.Equal(CommClass.Healthy, target.BadComm.Classifier.Classify(1).Class);
        Assert.Equal(123, target.Delay.NextDelayMs(CommunicationDirection.Push));
        Assert.Equal(7, target.Delay.NextDelayMs());
    }

    [Fact]
    public void LegacyImportAppliesToBothDirections()
    {
        var target = Create();
        string json = JsonSerializer.Serialize(new { Kind = ConfigBundleService.BadCommKind,
            Payload = new BadCommFile { BadComm = Offline(), NetworkDelay = new DelayRange { LowerMs = 17, UpperMs = 17 } } });
        target.Bundle.ImportBadComm(json);
        foreach (var direction in Enum.GetValues<CommunicationDirection>())
        {
            Assert.Equal(CommClass.NonComm, target.BadComm.GetClassifier(direction).Classify(1).Class);
            Assert.Equal(17, target.Delay.NextDelayMs(direction));
        }
    }

    [Fact]
    public void InvalidPushImportDoesNotPartiallyApplyPull()
    {
        var target = Create();
        string json = JsonSerializer.Serialize(new { Kind = ConfigBundleService.BadCommKind,
            Payload = new BadCommFile { PullBadComm = Offline(), PushNetworkDelay = new DelayRange { LowerMs = -1 } } });
        Assert.Throws<ArgumentException>(() => target.Bundle.ImportBadComm(json));
        Assert.False(target.BadComm.Snapshot().Enabled);
    }

    [Fact]
    public void CompositionSeparatesDirectionsAtTheSameInitialGeneration()
    {
        var store = new Store();
        store.Current.PullBadComm = Offline();
        store.Current.PushBadComm = new BadCommConfig { Enabled = false };
        var meters = new MeterRegistry();
        meters.AddBatch("fleet", "template.xml", 10);
        var cache = new FleetCompositionCache(meters, new BadCommSettings(store));
        Assert.Equal(10, cache.Current(CommunicationDirection.Pull).NonComm);
        Assert.Equal(10, cache.Current(CommunicationDirection.Push).Healthy);
        Assert.Equal(10, cache.Current(CommunicationDirection.Pull).NonComm);
    }

    private static (BadCommSettings BadComm, NetworkDelaySettings Delay, ConfigBundleService Bundle) Create()
    {
        var store = new Store();
        var badComm = new BadCommSettings(store);
        var delay = new NetworkDelaySettings(Options.Create(new NetworkDelayOptions()), store);
        return (badComm, delay, new ConfigBundleService(new MeterRegistry(), new NetworkRegistry(), badComm, delay));
    }

    private sealed class Store : IRuntimeConfigStore
    {
        public MayaRuntimeConfig Current { get; set; } = new();
        public void Update(Action<MayaRuntimeConfig> mutate) => mutate(Current);
    }
}
