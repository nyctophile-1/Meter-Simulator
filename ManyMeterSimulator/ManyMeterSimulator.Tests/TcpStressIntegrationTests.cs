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
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public class TcpStressIntegrationTests
{
    [Fact]
    public async Task ServicePreparesRealDlmsFramesThenFiresFromTheMetersAddress()
    {
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var f = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port);
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
    public async Task StoppedBatchesAndUnsupportedProfilesAreRejected()
    {
        var f = new Fixture(4059);
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Push.OpenTcpRunAsync(f.Request with { PushSetupLogicalName = "missing" }));
        f.Batches.TryStop(f.Batch.Id);
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Push.OpenTcpRunAsync(f.Request));
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
        public TcpPushRequest Request => new() { BatchIds = [Batch.Id] };
        public Fixture(int port)
        {
            Network.AddPushTarget(new() { Key = "tcp", Address = "::1", Port = port }, true);
            Batch = Batches.AddBatch("TCP", "SA1231166HP_values.xml", 1, NicType.Tcp4G, null, "tcp");
            Batches.TryStart(Batch.Id);
            var templates = new TemplateRegistry(Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
                new Host(), NullLogger<TemplateRegistry>.Instance);
            var sessions = new MeterSessionManager(Batches, templates, Options.Create(new BrainOptions()),
                Options.Create(new TcpOptions { AddressPrefix = "::/80" }), NullLogger<MeterSessionManager>.Instance);
            var options = Options.Create(new PushOptions());
            Push = new(Batches, sessions, Network, new TcpPushSender(NullLogger<TcpPushSender>.Instance, options),
                new NoMqtt(), new NicCodecFactory(), options, Options.Create(new CustomPushOptions()),
                new SimulatorMetrics(), NullLogger<PushCoordinator>.Instance);
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
}
