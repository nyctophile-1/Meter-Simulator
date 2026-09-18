using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Push;
using ManyMeterSimulator.Settings;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public partial class MqttPushRunTests
{
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task OrdinaryPushUsesOnlyPushImpairmentAndDelay(bool pullOffline, bool pushOffline)
    {
        var fixture = new Fixture(1);
        var store = new DirectionalStore();
        var badComm = new BadCommSettings(store);
        var delay = new NetworkDelaySettings(Options.Create(new NetworkDelayOptions()), store);
        foreach (var direction in Enum.GetValues<CommunicationDirection>())
            Assert.True(badComm.TryUpdate(new BadCommConfig
            {
                Enabled = direction == CommunicationDirection.Pull ? pullOffline : pushOffline,
                Auto = new AutoAllocation { NonCommPercent = 100, BadCommPercent = 0 },
            }, out _, direction));
        Assert.True(delay.TryUpdate(10_000, 10_000, CommunicationDirection.Pull));
        Assert.True(delay.TryUpdate(0, 0, CommunicationDirection.Push));
        var options = Options.Create(new PushOptions { UseCiphering = false });
        var push = new PushCoordinator(fixture.Batches, fixture.Sessions, fixture.Network,
            new TcpPushSender(NullLogger<TcpPushSender>.Instance, options), fixture.Publisher,
            new NicCodecFactory(), options, Options.Create(new CustomPushOptions()), fixture.Metrics,
            NullLogger<PushCoordinator>.Instance, CustomPushFixtureModel.DailyEncoder(93),
            badComm: badComm, networkDelay: delay);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var result = await push.PushBatchAsync(fixture.Batch.Id, cancellationToken: timeout.Token,
            pushSetupLogicalName: MqttPushProfiles.CustomDaily);
        Assert.Equal(pushOffline ? 0 : 1, result.Sent);
        Assert.Equal(pushOffline ? 1 : 0, result.Skipped);
        Assert.Equal(pushOffline ? 0 : 1, fixture.Publisher.Messages.Count);
    }

    private sealed class DirectionalStore : IRuntimeConfigStore
    {
        public MayaRuntimeConfig Current { get; } = new();
        public void Update(Action<MayaRuntimeConfig> mutate) => mutate(Current);
    }
}
