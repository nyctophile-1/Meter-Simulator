using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Gurux.DLMS;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Secure;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using ManyMeterSimulator.Settings;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Authentication = Gurux.DLMS.Enums.Authentication;
using Command = Gurux.DLMS.Enums.Command;
using DataType = Gurux.DLMS.Enums.DataType;
using InterfaceType = Gurux.DLMS.Enums.InterfaceType;
using Security = Gurux.DLMS.Enums.Security;

namespace ManyMeterSimulator.Tests;

public sealed class TcpAssociationLifetimeTests
{
    [Theory]
    [InlineData("peer-close")]
    [InlineData("partial-frame")]
    [InlineData("idle-timeout")]
    public async Task DisconnectClearsAuthenticatedAssociationAndPreservesMeterState(string ending)
    {
        await using var harness = new Harness();
        await harness.StartAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var first = await harness.ConnectAsync(timeout.Token);
        var secure = SecureClient();
        NetworkStream stream = first.GetStream();
        await AuthenticateAsync(stream, secure, timeout.Token);

        var balance = new GXDLMSData("0.0.94.91.24.255") { Value = 4321 };
        balance.SetDataType(2, DataType.Int32);
        Assert.Equal(0, (await ExchangeAsync(stream, secure, secure.Write(balance, 2)[0], timeout.Token)).Error);

        var session = harness.Brains.GetOrCreate(harness.Meter);
        uint counterBeforeClose = session.Ciphering.InvocationCounter;
        long successfulBeforeClose = session.SuccessfulCommands;
        Assert.True(counterBeforeClose > 0);
        Assert.Equal(48, session.Settings.ClientAddress);

        if (ending == "idle-timeout")
        {
            Assert.Single(harness.Sessions.Snapshot()).CancelDueToIdleTimeout();
        }
        else
        {
            if (ending == "partial-frame")
            {
                await stream.WriteAsync(new byte[] { 0, 1, 0 }, timeout.Token);
            }

            first.Client.Shutdown(SocketShutdown.Send);
        }

        await harness.WaitForNoSessionsAsync(timeout.Token);
        Assert.Same(session, harness.Brains.GetOrCreate(harness.Meter));
        Assert.Equal(counterBeforeClose, session.Ciphering.InvocationCounter);
        Assert.Equal(successfulBeforeClose, session.SuccessfulCommands);
        Assert.Equal(0, session.Settings.ClientAddress);

        using var second = await harness.ConnectAsync(timeout.Token);
        var publicClient = new GXDLMSClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        NetworkStream next = second.GetStream();
        GXReplyData association = await ExchangeAsync(next, publicClient, publicClient.AARQRequest()[0], timeout.Token);
        Assert.Equal(Command.Aare, association.Command);
        publicClient.ParseAAREResponse(association.Data);

        GXReplyData read = await ExchangeAsync(next, publicClient, publicClient.Read(balance, 2)[0], timeout.Token);
        Assert.Equal(0, read.Error);
        Assert.Equal(4321, Convert.ToInt32(read.Value));
        Assert.Same(session, harness.Brains.GetOrCreate(harness.Meter));
        second.Client.Shutdown(SocketShutdown.Send);
        await harness.WaitForNoSessionsAsync(timeout.Token);
    }

    [Fact]
    public async Task LiveAssociationSurvivesMultipleBlocksAndRejectedDuplicateConnection()
    {
        await using var harness = new Harness();
        await harness.StartAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var first = await harness.ConnectAsync(timeout.Token);
        var secure = SecureClient();
        NetworkStream stream = first.GetStream();
        await AuthenticateAsync(stream, secure, timeout.Token);

        using var duplicate = await harness.ConnectAsync(timeout.Token);
        Assert.Equal(0, await duplicate.GetStream().ReadAsync(new byte[8], timeout.Token));
        Assert.Equal(48, harness.Brains.GetOrCreate(harness.Meter).Settings.ClientAddress);

        var profile = new GXDLMSProfileGeneric("1.0.99.2.0.255");
        GXReplyData blocks = await ExchangeAsync(stream, secure, secure.Read(profile, 2)[0], timeout.Token);
        Assert.True(blocks.IsMoreData);
        int exchanges = 1;

        while (blocks.IsMoreData)
        {
            blocks = await ExchangeAsync(stream, secure, secure.ReceiverReady(blocks), timeout.Token, blocks);
            Assert.True(++exchanges < 100);
        }

        Assert.Equal(0, blocks.Error);
        Assert.Equal(48, harness.Brains.GetOrCreate(harness.Meter).Settings.ClientAddress);
        Assert.Equal(1, harness.Sessions.ActiveCount);
        first.Client.Shutdown(SocketShutdown.Send);
        await harness.WaitForNoSessionsAsync(timeout.Token);
    }

    [Fact]
    public async Task EmptyConnectionDoesNotMaterializeMeterState()
    {
        await using var harness = new Harness();
        await harness.StartAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var client = await harness.ConnectAsync(timeout.Token);

        while (harness.Sessions.ActiveCount == 0)
        {
            await Task.Delay(10, timeout.Token);
        }

        client.Client.Shutdown(SocketShutdown.Send);
        await harness.WaitForNoSessionsAsync(timeout.Token);
        Assert.Equal(0, harness.Brains.LiveMeterCount);
    }

    private static GXDLMSSecureClient SecureClient()
    {
        var client = new GXDLMSSecureClient(true, 48, 1, Authentication.High,
            "AAAAAAAAAAAAAAAA", InterfaceType.WRAPPER) { MaxReceivePDUSize = 128 };
        client.Ciphering.Security = Security.AuthenticationEncryption;
        client.Ciphering.BlockCipherKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
        client.Ciphering.AuthenticationKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
        client.Ciphering.SystemTitle = Encoding.ASCII.GetBytes("METRTEST");

        return client;
    }

    private static async Task AuthenticateAsync(NetworkStream stream, GXDLMSSecureClient client,
        CancellationToken cancellationToken)
    {
        GXReplyData association = await ExchangeAsync(stream, client, client.AARQRequest()[0], cancellationToken);
        client.ParseAAREResponse(association.Data);
        GXReplyData authentication = await ExchangeAsync(stream, client,
            client.GetApplicationAssociationRequest()[0], cancellationToken);
        client.ParseApplicationAssociationResponse(authentication.Data);
    }

    private static async Task<GXReplyData> ExchangeAsync(NetworkStream stream, GXDLMSClient client,
        byte[] request, CancellationToken cancellationToken, GXReplyData? reply = null)
    {
        await stream.WriteAsync(request, cancellationToken);
        var header = new byte[8];
        await stream.ReadExactlyAsync(header, cancellationToken);
        int length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(6, 2));
        var response = new byte[8 + length];
        header.CopyTo(response, 0);
        await stream.ReadExactlyAsync(response.AsMemory(8), cancellationToken);
        reply ??= new GXReplyData();
        Assert.True(client.GetData(new GXByteBuffer(response), reply));

        return reply;
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly TcpNicListenerService service;
        private readonly Lifetime lifetime = new();
        private readonly int port;

        public Harness()
        {
            using var probe = new TcpListener(IPAddress.IPv6Loopback, 0);
            probe.Start();
            port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();

            var meters = new MeterRegistry();
            MeterBatch batch = meters.AddBatch("tcp", "SA1231166HP_values.xml", 1);
            meters.TryStart(batch.Id);
            var templates = new TemplateRegistry(
                Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
                new HostEnvironment(), NullLogger<TemplateRegistry>.Instance);
            var tcpOptions = Options.Create(new TcpOptions { ListenPort = port, ShutdownDrainSeconds = 0 });
            Brains = new MeterSessionManager(meters, templates, Options.Create(new BrainOptions()),
                tcpOptions, NullLogger<MeterSessionManager>.Instance);
            var metrics = new SimulatorMetrics();
            var config = new RuntimeConfig();
            var bridge = new BrainMeterSimBridge(Brains, NullLogger<BrainMeterSimBridge>.Instance, metrics);
            service = new TcpNicListenerService(NullLogger<TcpNicListenerService>.Instance, tcpOptions,
                Sessions, new MeterAdmission(meters, templates, Sessions, metrics), bridge, metrics,
                new NetworkDelaySettings(Options.Create(new NetworkDelayOptions()), config),
                new BadCommSettings(config), lifetime);
        }

        public SessionRegistry Sessions { get; } = new();
        public MeterSessionManager Brains { get; }
        public MeterRef Meter { get; } = MeterRef.FromTcpAddress(IPAddress.IPv6Loopback);

        public Task StartAsync()
        {
            return service.StartAsync(CancellationToken.None);
        }

        public async Task<TcpClient> ConnectAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                var client = new TcpClient(AddressFamily.InterNetworkV6);

                try
                {
                    await client.ConnectAsync(IPAddress.IPv6Loopback, port, cancellationToken);

                    return client;
                }
                catch (SocketException)
                {
                    client.Dispose();
                    await Task.Delay(10, cancellationToken);
                }
            }
        }

        public async Task WaitForNoSessionsAsync(CancellationToken cancellationToken)
        {
            while (Sessions.ActiveCount != 0)
            {
                await Task.Delay(10, cancellationToken);
            }
        }

        public async ValueTask DisposeAsync()
        {
            lifetime.StopApplication();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            try
            {
                await service.StopAsync(timeout.Token);
            }
            finally
            {
                service.Dispose();
                lifetime.Dispose();
            }
        }
    }

    private sealed class RuntimeConfig : IRuntimeConfigStore
    {
        public MayaRuntimeConfig Current { get; } = new();

        public void Update(Action<MayaRuntimeConfig> mutate)
        {
            mutate(Current);
        }
    }

    private sealed class HostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class Lifetime : IHostApplicationLifetime, IDisposable
    {
        private readonly CancellationTokenSource stopping = new();

        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => stopping.Token;
        public CancellationToken ApplicationStopped => CancellationToken.None;

        public void StopApplication()
        {
            stopping.Cancel();
        }

        public void Dispose()
        {
            stopping.Dispose();
        }
    }
}
