using System.Net;
using System.Net.Sockets;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using ManyMeterSimulator.Testing;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Settings;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public partial class TcpStressIntegrationTests
{
    [Fact]
    public async Task SavedTcpLoopReloadsAndStopPersistsItsTotals()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var f = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port,
            badComm: HistoricalPushTests.Impaired(CommClass.NonComm), networkDelay: StressDelay());
        string directory = Path.Combine(Path.GetTempPath(), "maya-tcp-plan-" + Guid.NewGuid().ToString("N"));
        var persistence = Options.Create(new PersistenceOptions { Folder = directory });
        var host = new Host();
        var store = new JsonTestPlanStore(persistence, host, NullLogger<JsonTestPlanStore>.Instance);
        var registry = new TestPlanRegistry(store);
        var plan = new TestPlan { Name = "TCP loop", Tasks = [new TcpStressLoopTask
        {
            DurationMinutes = 0, CyclePauseSeconds = 5, EnvironmentKey = "tcp",
            Request = f.Request with { MaxConcurrency = 256, PushSetupLogicalName = "0.0.25.9.0.255" },
        }] };
        registry.AddPlan(plan);
        var restored = new TestPlanRegistry(store).Plan(plan.Id)!;
        Assert.True(restored.RunsUntilStopped);
        Assert.Equal(256, Assert.IsType<TcpStressLoopTask>(Assert.Single(restored.Tasks)).Request.MaxConcurrency);
        var reports = new TestRunStore(persistence, host, NullLogger<TestRunStore>.Instance);
        var runtime = new RuntimeStore();
        await using var engine = new TestRunEngine(f.Batches, f.Network, f.Push, f.Sessions,
            new SessionRegistry(), new SimulatorMetrics(), reports, new BadCommSettings(runtime),
            new NetworkDelaySettings(Options.Create(new NetworkDelayOptions()), runtime), NullLogger<TestRunEngine>.Instance);
        engine.ScheduleRun(restored, "TCP stop", DateTimeOffset.UtcNow);
        using var client = await listener.AcceptTcpClientAsync(timeout.Token);
        using var received = new MemoryStream();
        await client.GetStream().CopyToAsync(received, timeout.Token);
        engine.StopNow();
        while (engine.IsActive) await Task.Delay(10, timeout.Token);
        var report = reports.Load(engine.ActiveRun!.RunId)!;
        Assert.Equal(TestRunStatus.Stopped, report.FinalStatus);
        Assert.Equal(1, Assert.Single(report.Tasks).TcpLoop!.Totals.MessagesSent);
    }

    [Fact]
    public async Task ServicePreparesRealDlmsFramesThenFiresFromTheMetersAddress()
    {
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var f = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port,
            badComm: HistoricalPushTests.Impaired(CommClass.NonComm), networkDelay: StressDelay());
        await using var service = new TcpStressService(f.Push, new Lifetime());
        service.Start(f.Request, prepare: true);
        await WaitFor(service, "Ready");
        Assert.False(listener.Pending());
        Assert.True(service.State.PreparedMessages > 0);
        var accept = listener.AcceptTcpClientAsync();
        service.Fire();
        using var client = await accept.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(IPAddress.IPv6Loopback, ((IPEndPoint)client.Client.RemoteEndPoint!).Address);
        using var received = new MemoryStream();
        await client.GetStream().CopyToAsync(received).WaitAsync(TimeSpan.FromSeconds(5));
        await WaitFor(service, "Completed");
        Assert.True(received.Length > 30);
        Assert.Equal(1, service.State.Result!.MetersSent);
        Assert.Equal(0, service.State.Result.MessagesFailed);
    }

    [Fact]
    public async Task DisablingTargetInvalidatesPreparedRunWithoutSending()
    {
        var f = new Fixture(4059);
        await using var run = await f.Push.OpenTcpRunAsync(f.Request);
        await run.PrepareAsync();
        f.Network.SetPushTargetEnabled("tcp", false);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.FireAsync());
    }

    [Fact]
    public async Task ServiceRetainsZeroSendTotalsWhenPreparedTargetChangesBeforeFire()
    {
        var f = new Fixture(4059);
        await using var service = new TcpStressService(f.Push, new Lifetime());
        service.Start(f.Request, prepare: true);
        await WaitFor(service, "Ready");
        f.Network.SetPushTargetEnabled("tcp", false);
        service.Fire();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (service.State.Phase != "Failed") await Task.Delay(10, timeout.Token);
        Assert.NotNull(service.State.Result);
        Assert.Equal(0, service.State.Result.MessagesSent);
        Assert.Equal(0, service.State.Result.MetersSent);
    }

    [Fact]
    public async Task StoppedBatchesAndUnsupportedProfilesAreRejected()
    {
        var f = new Fixture(4059);
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Push.OpenTcpRunAsync(f.Request with { PushSetupLogicalName = "missing" }));
        f.Batches.TryStop(f.Batch.Id);
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Push.OpenTcpRunAsync(f.Request));
    }

    private static NetworkDelaySettings StressDelay() => new(Options.Create(new NetworkDelayOptions()),
        new RuntimeStore { Current = { NetworkDelay = new DelayRange { LowerMs = 10000, UpperMs = 10000 } } });

    [Theory]
    [InlineData(CommClass.Healthy)]
    [InlineData(CommClass.BadComm)]
    [InlineData(CommClass.NonComm)]
    public async Task LiveTcpStressBypassesSimulatedFailuresAndDelay(CommClass classification)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var f = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port,
            badComm: HistoricalPushTests.Impaired(classification), networkDelay: StressDelay());
        await using var run = await f.Push.OpenTcpRunAsync(f.Request, timeout.Token);
        var sending = run.SendLiveAsync();
        using var client = await listener.AcceptTcpClientAsync(timeout.Token);
        using var received = new MemoryStream();
        await client.GetStream().CopyToAsync(received, timeout.Token);
        var result = await sending;
        Assert.NotEmpty(received.ToArray());
        Assert.Equal(1, result.MetersSent);
        Assert.Equal(0, result.MetersSkipped);
        Assert.Equal(0, result.MessagesFailed);
    }
    private static async Task WaitFor(TcpStressService service, string phase)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (service.State.Phase != phase)
        {
            Assert.NotEqual("Failed", service.State.Phase);
            await Task.Delay(10, timeout.Token);
        }
    }

    private sealed class Fixture
    {
        public MeterRegistry Batches { get; } = new();
        public NetworkRegistry Network { get; } = new();
        public MeterBatch Batch { get; }
        public PushCoordinator Push { get; }
        public MeterSessionManager Sessions { get; }
        public TcpPushRequest Request => new() { BatchIds = [Batch.Id], WaitForPeerCloseSeconds = 0 };
        public Fixture(int port, string template = "SA1231166HP_values.xml", BadCommSettings? badComm = null, NetworkDelaySettings? networkDelay = null)
        {
            Network.AddPushTarget(new() { Key = "tcp", Address = "::1", Port = port }, true);
            Batch = Batches.AddBatch("TCP", template, 1, NicType.Tcp4G, null, "tcp");
            Batches.TryStart(Batch.Id);
            var templates = new TemplateRegistry(Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
                new Host(), NullLogger<TemplateRegistry>.Instance);
            Sessions = new MeterSessionManager(Batches, templates, Options.Create(new BrainOptions()),
                Options.Create(new TcpOptions { AddressPrefix = "::/80" }), NullLogger<MeterSessionManager>.Instance);
            var options = Options.Create(new PushOptions());
            Push = new(Batches, Sessions, Network, new TcpPushSender(NullLogger<TcpPushSender>.Instance, options),
                new NoMqtt(), new NicCodecFactory(), options, Options.Create(new CustomPushOptions()),
                new SimulatorMetrics(), NullLogger<PushCoordinator>.Instance, badComm: badComm, networkDelay: networkDelay);
        }
    }

    private sealed class NoMqtt : IMqttPushPublisher
    {
        public bool HasClient(BrokerBinding binding) => throw new NotSupportedException();
        public Task<bool> TryPublishPushAsync(BrokerBinding binding, NicPublish publish, int qos, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IMqttPushPool> OpenPoolAsync(BrokerBinding binding, int publisherCount, int qos, int publishTimeoutSeconds, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
    private sealed class Host : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Tests";
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
    private sealed class Lifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication() { }
    }
    private sealed class RuntimeStore : IRuntimeConfigStore
    {
        public MayaRuntimeConfig Current { get; } = new();
        public void Update(Action<MayaRuntimeConfig> mutate) => mutate(Current);
    }
}
