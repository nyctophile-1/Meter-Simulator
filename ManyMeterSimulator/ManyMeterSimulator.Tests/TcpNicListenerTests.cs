using System.Net;
using System.Net.Sockets;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Framing;
using ManyMeterSimulator.MqttBridge;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using ManyMeterSimulator.Settings;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// End-to-end over a real socket: accept → derive the meter from the connection → admission gates →
/// session registry → WPDU framing → bridge → write the reply back. Uses the echo bridge so the
/// assertion is about the NIC plumbing, not DLMS semantics.
///
/// This is the regression net for the identity refactor (virtual_nics.md Phase A): the TCP path must
/// behave identically now that it resolves a MeterRef and registers by index instead of by IPAddress.
/// Loopback (::1) carries index 1 in its low 48 bits, so it is meter 1 of the first batch.
/// </summary>
public class TcpNicListenerTests
{
    private const string Template = "SA1231166HP_values.xml";

    [Fact]
    public async Task Frame_RoundTripsThroughTheListener_ForAProvisionedRunningMeter()
    {
        using var harness = new ListenerHarness(startBatch: true);
        await harness.StartAsync();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.IPv6Loopback, harness.Port);
        await using NetworkStream stream = client.GetStream();

        byte[] payload = [0x60, 0x1D, 0xA1, 0x09];   // arbitrary opaque APDU bytes
        byte[] request = DlmsWpduFramer.BuildFrame(sourceWPort: 16, destinationWPort: 1, payload);

        await stream.WriteAsync(request);

        byte[] reply = new byte[request.Length];
        int read = 0;
        while (read < reply.Length)
        {
            int n = await stream.ReadAsync(reply.AsMemory(read));
            Assert.True(n > 0, "connection closed before the full reply arrived");
            read += n;
        }

        Assert.Equal(request, reply);           // echo bridge returns the frame verbatim
        Assert.Equal(1, harness.Metrics.Snapshot(0).TotalAccepted);
        Assert.Equal(1, harness.Metrics.Snapshot(0).TotalExchanges);

        await harness.StopAsync();
    }

    [Fact]
    public async Task Connection_IsRejected_WhenTheBatchIsNotRunning()
    {
        using var harness = new ListenerHarness(startBatch: false);
        await harness.StartAsync();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.IPv6Loopback, harness.Port);
        await using NetworkStream stream = client.GetStream();

        // The listener closes without reading; a read must therefore hit EOF rather than a reply.
        byte[] request = DlmsWpduFramer.BuildFrame(16, 1, [0x60]);
        try
        {
            await stream.WriteAsync(request);
            int n = await stream.ReadAsync(new byte[8]);
            Assert.Equal(0, n);
        }
        catch (IOException)
        {
            // A reset instead of a clean EOF is equally valid evidence of rejection.
        }

        Assert.Equal(1, harness.Metrics.Snapshot(0).TotalRejectedBatchNotRunning);
        Assert.Equal(0, harness.Metrics.Snapshot(0).TotalAccepted);

        await harness.StopAsync();
    }

    private sealed class ListenerHarness : IDisposable
    {
        private readonly TcpNicListenerService _service;

        public ListenerHarness(bool startBatch)
        {
            Port = FreeTcpPort();

            var registry = new MeterRegistry();
            MeterBatch batch = registry.AddBatch("b1", Template, 10);
            if (startBatch)
            {
                registry.TryStart(batch.Id);
            }

            var templates = new TemplateRegistry(
                Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
                new TestHostEnvironment(),
                NullLogger<TemplateRegistry>.Instance);

            Metrics = new SimulatorMetrics();
            var sessions = new SessionRegistry();

            // Delay and impairment stay at their defaults (off), so this remains a test of
            // admission → framing → bridge rather than of the BadComm feature.
            var runtimeConfig = new InMemoryRuntimeConfigStore();

            _service = new TcpNicListenerService(
                NullLogger<TcpNicListenerService>.Instance,
                Options.Create(new TcpOptions { ListenPort = Port, ShutdownDrainSeconds = 1 }),
                sessions,
                new MeterAdmission(registry, templates, sessions, Metrics),
                new SimulatedMeterSimBridge(Options.Create(new SimulatedBridgeOptions { RoundTripDelayMs = 0 })),
                Metrics,
                new NetworkDelaySettings(Options.Create(new NetworkDelayOptions()), runtimeConfig),
                new BadCommSettings(runtimeConfig),
                new TestLifetime());
        }

        public int Port { get; }

        public SimulatorMetrics Metrics { get; }

        public Task StartAsync() => _service.StartAsync(CancellationToken.None);

        public async Task StopAsync()
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await _service.StopAsync(timeout.Token);
        }

        public void Dispose() => _service.Dispose();

        private static int FreeTcpPort()
        {
            var probe = new TcpListener(IPAddress.IPv6Loopback, 0);
            probe.Start();
            int port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();
            return port;
        }
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    /// <summary>
    /// Runtime config that never touches disk. The real store writes a JSON file next to the batch
    /// store, which would make these socket tests share mutable state across runs.
    /// </summary>
    private sealed class InMemoryRuntimeConfigStore : IRuntimeConfigStore
    {
        public MayaRuntimeConfig Current { get; } = new();

        public void Update(Action<MayaRuntimeConfig> mutate) => mutate(Current);
    }

    private sealed class TestLifetime : IHostApplicationLifetime
    {
        private readonly CancellationTokenSource _started = new();
        private readonly CancellationTokenSource _stopping = new();
        private readonly CancellationTokenSource _stopped = new();

        public CancellationToken ApplicationStarted => _started.Token;
        public CancellationToken ApplicationStopping => _stopping.Token;
        public CancellationToken ApplicationStopped => _stopped.Token;

        public void StopApplication() => _stopping.Cancel();
    }
}
