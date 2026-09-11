using System.Diagnostics;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using ManyMeterSimulator.Settings;
using ManyMeterSimulator.Testing;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public partial class MqttPushRunTests
{
    [Fact]
    public async Task ContinuousLoopReusesConnections_RegeneratesPayloads_AndKeepsPartialPassTotals()
    {
        var fixture = new Fixture(3);
        using var stop = new CancellationTokenSource();
        fixture.Publisher.AfterPublish = () => { if (fixture.Publisher.Messages.Count == 7) stop.Cancel(); };
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request with { PublisherCount = 1, MaxConcurrency = 1 }, stop.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.SendLoopAsync(new()));

        Assert.Single(fixture.Publisher.Pools);
        Assert.Equal(2, run.LoopResult!.CompletedCycles);
        Assert.Equal(7, run.LoopResult.Totals.MessagesSent);
        Assert.Equal(7, run.LoopResult.Totals.MetersSent);
        var messages = fixture.Publisher.Messages.ToArray();
        Assert.Equal(messages[0].Topic, messages[3].Topic);
        Assert.NotEqual(messages[0].Payload, messages[3].Payload);
        Assert.Equal(0, fixture.Sessions.LiveMeterCount);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.SendLiveAsync());
    }

    [Fact]
    public async Task AllProfilesLoopsThroughEveryConfiguredDlmsPushSetupWithFreshCipheredFrames()
    {
        var fixture = new Fixture(1, ciphering: true);
        var batch = fixture.Batches.AddBatch("DLMS", "SA1231166HP_values.xml", 1, NicType.Mqtt4G, null, "local");
        fixture.Batches.TryStart(batch.Id);
        using var stop = new CancellationTokenSource();
        fixture.Publisher.AfterPublish = () => { if (fixture.Publisher.Messages.Count >= 6) stop.Cancel(); };
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request with { BatchIds = [batch.Id] }, stop.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.SendLoopAsync(new()));
        var messages = fixture.Publisher.Messages.ToArray();
        Assert.Equal(6, messages.Length); // instant + block load, repeated three times
        Assert.Equal(3, run.LoopResult!.Totals.MetersSent);
        Assert.NotEqual(messages[0].Payload, messages[2].Payload);
        Assert.Single(fixture.Publisher.Pools);
    }

    [Fact]
    public async Task InvalidProfileIsRejectedBeforeOpeningConnections_InsteadOfSendingDailySilently()
    {
        var fixture = new Fixture(1);
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Push.OpenMqttRunAsync(fixture.Request with
        { PushSetupLogicalName = "0.0.25.9.0.255" }));
        Assert.Empty(fixture.Publisher.Pools);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request with { PushSetupLogicalName = MqttPushProfiles.CustomDaily });
        Assert.Equal(1, (await run.SendLiveAsync()).MessagesSent);
    }

    [Fact]
    public async Task AllRejectedLoopStopsAfterOnePass()
    {
        var fixture = new Fixture(3);
        fixture.Publisher.Reject = true;
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.SendLoopAsync(new()));
        Assert.Equal(1, run.LoopResult!.CompletedCycles);
        Assert.Equal(3, run.LoopResult.Totals.MessagesFailed);
        Assert.Equal(3, fixture.Publisher.Messages.Count);
    }

    [Fact]
    public async Task ServiceStopInterruptsCyclePauseAndRetainsTotals()
    {
        var fixture = new Fixture(3);
        var sent = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Publisher.AfterPublish = () => { if (fixture.Publisher.Messages.Count >= 3) sent.TrySetResult(); };
        await using var service = new MqttStressService(fixture.Push, new TestLifetime());
        service.Start(fixture.Request, false, new() { CyclePauseSeconds = 3600 });
        await sent.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await service.StopAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("Stopped", service.State.Phase);
        Assert.Equal(3, service.State.Result!.MessagesSent);
        Assert.NotNull(service.State.Loop);
        Assert.All(fixture.Publisher.Pools, p => Assert.True(p.Disposed));
        int count = fixture.Publisher.Messages.Count;
        await Task.Delay(20);
        Assert.Equal(count, fixture.Publisher.Messages.Count);
    }

    [Fact]
    public async Task BatchChangeStopsContinuousServiceAndReleasesConnections()
    {
        var fixture = new Fixture(3);
        fixture.Publisher.AfterPublish = () => fixture.Batches.TryStop(fixture.Batch.Id);
        await using var service = new MqttStressService(fixture.Push, new TestLifetime());
        service.Start(fixture.Request, false, new());
        await WaitUntil(() => service.State.Phase == "Failed" && fixture.Publisher.Pools.All(p => p.Disposed));
        Assert.Contains("changed", service.State.Detail);
        Assert.NotNull(service.State.Result);
    }

    [Fact]
    public async Task DurationCompletesNormallyAndCancelsAnOutstandingPublish()
    {
        var fixture = new Fixture(1);
        // Exercise the production one-minute deadline; no actual network traffic or busy loop.
        fixture.Publisher.BeforePublish = ct => Task.Delay(Timeout.Infinite, ct);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request);
        var watch = Stopwatch.StartNew();
        var summary = await run.SendLoopAsync(new() { DurationMinutes = 1 }).WaitAsync(TimeSpan.FromSeconds(75));
        Assert.InRange(watch.Elapsed.TotalSeconds, 59, 74);
        Assert.Equal(0, summary.CompletedCycles);
        Assert.Equal(0, summary.Totals.MessagesSent);
    }

    [Fact]
    public async Task SavedLoopPlanReloadsAndStopPersistsReportTotals()
    {
        var fixture = new Fixture(3);
        string directory = Path.Combine(Path.GetTempPath(), "maya-loop-test-" + Guid.NewGuid().ToString("N"));
        var persistence = Options.Create(new PersistenceOptions { Folder = directory });
        var env = new TestEnvironment();
        var planStore = new JsonTestPlanStore(persistence, env, NullLogger<JsonTestPlanStore>.Instance);
        var registry = new TestPlanRegistry(planStore);
        var plan = new TestPlan { Name = "Continuous custom plan", Tasks = [new MqttStressLoopTask
        {
            Label = "All profiles", DurationMinutes = 0, CyclePauseSeconds = 0,
            EnvironmentKey = fixture.Batch.EnvironmentKey,
            Request = fixture.Request with { PublisherCount = 1, Qos = 1, MaxConcurrency = 1, PushSetupLogicalName = MqttPushProfiles.CustomDaily },
        }] };
        registry.AddPlan(plan);
        var reloaded = new TestPlanRegistry(planStore).Plan(plan.Id)!;
        var task = Assert.IsType<MqttStressLoopTask>(Assert.Single(reloaded.Tasks));
        Assert.True(reloaded.RunsUntilStopped);
        Assert.Equal(MqttPushProfiles.CustomDaily, task.Request.PushSetupLogicalName);
        Assert.Equal(1, task.Request.Qos);
        var reportStore = new TestRunStore(persistence, env, NullLogger<TestRunStore>.Instance);
        var runtimeStore = new LoopRuntimeStore();
        await using var engine = new TestRunEngine(fixture.Batches, fixture.Network, fixture.Push, fixture.Sessions,
            new SessionRegistry(), new SimulatorMetrics(), reportStore, new BadCommSettings(runtimeStore),
            new NetworkDelaySettings(Options.Create(new NetworkDelayOptions()), runtimeStore), NullLogger<TestRunEngine>.Instance);
        fixture.Publisher.AfterPublish = () => { if (fixture.Publisher.Messages.Count == 7) engine.StopNow(); };
        engine.ScheduleRun(reloaded, "stop test", DateTimeOffset.UtcNow);
        await WaitUntil(() => !engine.IsActive);
        var report = reportStore.Load(engine.ActiveRun!.RunId)!;
        Assert.Equal(TestRunStatus.Stopped, report.FinalStatus);
        var result = Assert.Single(report.Tasks).MqttLoop!;
        Assert.Equal(2, result.CompletedCycles);
        Assert.Equal(7, result.Totals.MessagesSent);
        Assert.All(fixture.Publisher.Pools, p => Assert.True(p.Disposed));
    }

    [Fact]
    public void ProfileDiscoveryIncludesAllNonEmptySetupsAndExcludesPlaceholders()
    {
        var profiles = MqttPushProfiles.ReadTemplate(Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        Assert.Equal(new[] { "0.0.25.9.0.255", "0.5.25.9.0.255" }, profiles.Select(p => p.LogicalName));
        string path = Path.Combine(Path.GetTempPath(), "maya-profiles-" + Guid.NewGuid().ToString("N") + ".xml");
        try
        {
            File.WriteAllText(path, "<Objects><GXDLMSPushSetup><LN>0.42.25.9.0.255</LN><ObjectList><Item /></ObjectList></GXDLMSPushSetup><GXDLMSPushSetup><LN>0.43.25.9.0.255</LN></GXDLMSPushSetup></Objects>");
            Assert.Equal("0.42.25.9.0.255", Assert.Single(MqttPushProfiles.ReadTemplate(path)).LogicalName);
        }
        finally { File.Delete(path); }
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!condition()) await Task.Delay(5, timeout.Token);
    }

    private sealed class LoopRuntimeStore : IRuntimeConfigStore
    {
        public MayaRuntimeConfig Current { get; } = new();
        public void Update(Action<MayaRuntimeConfig> mutate) => mutate(Current);
    }
}
