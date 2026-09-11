using System.Collections.Concurrent;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using ManyMeterSimulator.Testing;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public class MqttPushRunTests
{
    [Fact]
    public async Task StressServiceArmsWithoutPublishing_ThenFiresAndReleasesThePool()
    {
        var fixture = new Fixture(3);
        await using var service = new MqttStressService(fixture.Push, new TestLifetime());
        service.Start(fixture.Request, prepare: true);
        await WaitForPhase(service, "Ready");
        Assert.Equal(fixture.Request.BatchIds, service.State.Request!.BatchIds);
        Assert.Equal(fixture.Request.PublisherCount, service.State.Request.PublisherCount);
        Assert.Empty(fixture.Publisher.Messages);
        Assert.Throws<InvalidOperationException>(() => service.Start(fixture.Request, prepare: false));
        service.Fire();
        await WaitForPhase(service, "Completed");
        Assert.Equal(fixture.Request.Qos, service.State.Request!.Qos);
        Assert.Equal(3, service.State.Result!.MessagesSent);
        await service.StopAsync();
        Assert.All(fixture.Publisher.Pools, p => Assert.True(p.Disposed));
    }

    [Fact]
    public async Task DiscardingPreparedStressRunReleasesDataWithoutPublishing()
    {
        var fixture = new Fixture(3);
        await using var service = new MqttStressService(fixture.Push, new TestLifetime());
        service.Start(fixture.Request, prepare: true);
        await WaitForPhase(service, "Ready");
        await service.StopAsync();
        Assert.False(service.State.IsActive);
        Assert.Equal(0, service.State.PreparedMessages);
        Assert.Empty(fixture.Publisher.Messages);
        Assert.All(fixture.Publisher.Pools, p => Assert.True(p.Disposed));
        Assert.Throws<InvalidOperationException>(() => service.Fire());
    }

    private static async Task WaitForPhase(MqttStressService service, string phase)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (service.State.Phase != phase)
        {
            Assert.NotEqual("Failed", service.State.Phase);
            await Task.Delay(5, timeout.Token);
        }
    }

    private sealed class TestLifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication() { }
    }

    [Fact]
    public async Task PrepareSendsNothing_AndFireConsumesVerifiedPayloadsOnce()
    {
        var fixture = new Fixture(25);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request);
        await run.PrepareAsync();
        Assert.True(run.IsReady);
        Assert.Equal(25, run.PreparedMessages);
        Assert.Empty(fixture.Publisher.Messages);
        Assert.Equal(0, fixture.Sessions.LiveMeterCount); // custom push does not need DLMS sessions

        var result = await run.FireAsync();
        Assert.Equal(25, result.MessagesSent);
        Assert.Equal(25, result.MetersSent);
        Assert.Equal(0, result.MetersFailed);
        Assert.All(fixture.Publisher.Messages, m => Assert.Matches(@"^gw-event/received_data/sim-gw/sink1/\d+/10/10$", m.Topic));
        Assert.Equal(25, fixture.Publisher.Messages.Select(m => m.Topic).Distinct().Count());
        Assert.False(run.IsReady);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.FireAsync());
        Assert.Equal(25, fixture.Publisher.Messages.Count);
    }

    [Fact]
    public async Task MemoryBudgetFailureSendsNothing_AndCannotBeFired()
    {
        var fixture = new Fixture(5000);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request with { PreparedMemoryMiB = 1 });
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => run.PrepareAsync());
        Assert.Contains("memory budget", ex.Message);
        Assert.Empty(fixture.Publisher.Messages);
        Assert.False(run.IsReady);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.FireAsync());
    }

    [Fact]
    public async Task StoppedBatchInvalidatesPreparedData()
    {
        var fixture = new Fixture(3);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request);
        await run.PrepareAsync();
        fixture.Batches.TryStop(fixture.Batch.Id);
        Assert.False(run.IsReady);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.FireAsync());
        Assert.Empty(fixture.Publisher.Messages);
    }

    [Fact]
    public async Task ChangedBrokerInvalidatesPreparedData()
    {
        var fixture = new Fixture(3);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request);
        await run.PrepareAsync();
        fixture.Network.UpdateBroker(new BrokerEndpoint { Key = "local", Host = "changed.invalid" }, verified: false);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.FireAsync());
        Assert.Empty(fixture.Publisher.Messages);
    }

    [Fact]
    public async Task CancelledRunReleasesPublishers_AndNeverFires()
    {
        var fixture = new Fixture(3);
        using var cts = new CancellationTokenSource();
        var run = await fixture.Push.OpenMqttRunAsync(fixture.Request, cts.Token);
        await run.PrepareAsync();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.FireAsync());
        await run.DisposeAsync();
        Assert.All(fixture.Publisher.Pools, pool => Assert.True(pool.Disposed));
        Assert.Empty(fixture.Publisher.Messages);
    }

    [Fact]
    public async Task RejectedPublishesAreFailures_NotSuccessfulMeters()
    {
        var fixture = new Fixture(3);
        fixture.Publisher.Reject = true;
        var result = await fixture.Push.PushBatchAsync(fixture.Batch.Id);
        Assert.True(result.Ok);
        Assert.Equal(0, result.Sent);
        Assert.Equal(3, result.Failed);
        Assert.Contains("rejected", result.Error);
    }

    [Fact]
    public async Task TwoBatchesShareOnePool_AndBothContributeMessages()
    {
        var fixture = new Fixture(3);
        var second = fixture.Batches.AddBatch("second", "unused.xml", 4, NicType.MqttWirepas,
            93, "local", customPushHeaderKind: CustomPushHeaderKind.New);
        fixture.Batches.TryStart(second.Id);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request with { BatchIds = [fixture.Batch.Id, second.Id] });
        var result = await run.SendLiveAsync();
        Assert.Single(fixture.Publisher.Pools);
        Assert.Equal(7, result.MessagesSent);
        Assert.Equal(7, fixture.Publisher.Messages.Select(m => m.Topic).Distinct().Count());
    }

    [Fact]
    public async Task RandomPartialSelectionHasNoDuplicateMeters()
    {
        var fixture = new Fixture(100);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request with
        { MaximumMetersPerBatch = 99, SelectRandomly = true });
        var result = await run.SendLiveAsync();
        Assert.Equal(99, result.MetersSent);
        Assert.Equal(99, fixture.Publisher.Messages.Select(m => m.Topic).Distinct().Count());
    }

    [Fact]
    public async Task PreparedCipheredFramesAreRefusedBeforeGenerationOrSending()
    {
        var fixture = new Fixture(3, ciphering: true);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => run.PrepareAsync());
        Assert.Contains("UseCiphering", ex.Message);
        Assert.Empty(fixture.Publisher.Messages);
    }

    [Fact]
    public async Task ZeroAllocationInPartialPlanDoesNotOpenPublishers()
    {
        var fixture = new Fixture(3);
        var result = await fixture.Push.PushBatchAsync(fixture.Batch.Id, maximumMeters: 0);
        Assert.True(result.Ok);
        Assert.Equal(0, result.Total);
        Assert.Empty(fixture.Publisher.Pools);
    }

    private sealed class Fixture
    {
        public MeterRegistry Batches { get; } = new();
        public NetworkRegistry Network { get; } = new();
        public RecordingPublisher Publisher { get; } = new();
        public MeterSessionManager Sessions { get; }
        public PushCoordinator Push { get; }
        public MeterBatch Batch { get; }
        public MqttPushRequest Request => new() { BatchIds = [Batch.Id], PublisherCount = 4, MaxConcurrency = 8 };

        public Fixture(int count, bool ciphering = false)
        {
            Network.AddBroker(new BrokerEndpoint { Key = "local", Host = "unused.invalid" }, verified: true);
            Batch = Batches.AddBatch("custom", "unused.xml", count, NicType.MqttWirepas,
                93, "local", customPushHeaderKind: CustomPushHeaderKind.New);
            Batches.TryStart(Batch.Id);
            var templates = new TemplateRegistry(Options.Create(new TemplateOptions
            { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }), new TestEnvironment(), NullLogger<TemplateRegistry>.Instance);
            Sessions = new MeterSessionManager(Batches, templates, Options.Create(new BrainOptions()),
                Options.Create(new Networking.TcpOptions { AddressPrefix = "fd00:6d65:7472::/64" }), NullLogger<MeterSessionManager>.Instance);
            var options = Options.Create(new PushOptions { UseCiphering = ciphering });
            Push = new PushCoordinator(Batches, Sessions, Network, new TcpPushSender(NullLogger<TcpPushSender>.Instance, options),
                Publisher, new NicCodecFactory(), options, Options.Create(new CustomPushOptions()),
                new SimulatorMetrics(), NullLogger<PushCoordinator>.Instance);
        }
    }

    private sealed class RecordingPublisher : IMqttPushPublisher
    {
        public ConcurrentQueue<NicPublish> Messages { get; } = new();
        public List<RecordingPool> Pools { get; } = [];
        public bool Reject { get; set; }
        public bool HasClient(BrokerBinding binding) => true;
        public Task<bool> TryPublishPushAsync(BrokerBinding binding, NicPublish publish, int qos, CancellationToken cancellationToken)
            => throw new InvalidOperationException("The serialized listener publisher must not be used for push.");
        public Task<IMqttPushPool> OpenPoolAsync(BrokerBinding binding, int publisherCount, int qos,
            int publishTimeoutSeconds, CancellationToken cancellationToken)
        {
            var pool = new RecordingPool(this);
            Pools.Add(pool);
            return Task.FromResult<IMqttPushPool>(pool);
        }
    }

    private sealed class RecordingPool(RecordingPublisher owner) : IMqttPushPool
    {
        public bool Disposed { get; private set; }
        public bool IsConnected => !Disposed;
        public Task<MqttPushDelivery> PublishMeterAsync(IReadOnlyList<NicPublish> messages, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var message in messages) owner.Messages.Enqueue(message);
            return Task.FromResult(owner.Reject ? new MqttPushDelivery(0, messages.Count, "Broker rejected a publish.")
                : new MqttPushDelivery(messages.Count, 0));
        }
        public ValueTask DisposeAsync() { Disposed = true; return ValueTask.CompletedTask; }
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string ApplicationName { get; set; } = "tests";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public string EnvironmentName { get; set; } = "Test";
    }
}
