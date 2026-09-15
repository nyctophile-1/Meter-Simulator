using System.Net;
using System.Net.Sockets;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Push;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public class TcpPushSenderTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(256)]
    public async Task SendsAllFramesOnOneSourceBoundConnectionPerMeter(int meters)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start(512);
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var receive = Task.Run(async () =>
        {
            var readers = new List<Task>();
            for (int i = 0; i < meters; i++)
            {
                var client = await listener.AcceptTcpClientAsync(timeout.Token);
                readers.Add(Read(client));
            }
            await Task.WhenAll(readers);
        });
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions()));
        var results = await Task.WhenAll(Enumerable.Range(0, meters).Select(i => sender.SendAsync(i.ToString(),
            IPAddress.IPv6Loopback, $"[::1]:{port}", port, [new byte[] { 1, 2 }, new byte[] { 3, 4, 5 }], timeout.Token)));
        await receive;
        Assert.All(results, result => Assert.Equal(new PushDeliveryResult(2, 0), result));

        async Task Read(TcpClient client)
        {
            using (client)
            {
                Assert.Equal(IPAddress.IPv6Loopback, ((IPEndPoint)client.Client.RemoteEndPoint!).Address);
                using var bytes = new MemoryStream();
                await client.GetStream().CopyToAsync(bytes, timeout.Token);
                Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, bytes.ToArray());
            }
        }
    }

    [Fact]
    public async Task StrictSourceMismatchDoesNotConnectFromTheDefaultAddress()
    {
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions()));
        Assert.Equal(new PushDeliveryResult(0, 1), await sender.SendAsync("one", IPAddress.Loopback,
            $"[::1]:{port}", port, [new byte[] { 1 }]));
        Assert.False(listener.Pending());
    }

    [Fact]
    public async Task CallerCancellationIsPropagated()
    {
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions()));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sender.SendAsync("one", IPAddress.IPv6Loopback,
            "[::1]:4059", 4059, [new byte[] { 1 }], stop.Token));
    }
}
