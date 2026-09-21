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
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions { TcpSourcePort = 0 }));
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
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions { TcpSourcePort = 0 }));
        var result = await sender.SendAsync("one", IPAddress.Loopback, $"[::1]:{port}", port, [new byte[] { 1 }]);
        Assert.Equal(0, result.Sent);
        Assert.Equal(1, result.Failed);
        Assert.Contains("address family mismatch", result.Error);
        Assert.False(listener.Pending());
    }

    [Fact]
    public async Task RefusedConnectionReportsStageSourceAndDestination()
    {
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions { TcpSourcePort = 0 }));
        var result = await sender.SendAsync("one", IPAddress.IPv6Loopback, $"[::1]:{port}", port, [new byte[] { 1 }]);
        Assert.Equal(1, result.Failed);
        Assert.Contains("TCP connect failed", result.Error);
        Assert.Contains($"to ::1:{port}", result.Error);
        Assert.Contains("from ::1", result.Error);
    }

    [Fact]
    public async Task CallerCancellationIsPropagated()
    {
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions { TcpSourcePort = 0 }));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sender.SendAsync("one", IPAddress.IPv6Loopback,
            "[::1]:4059", 4059, [new byte[] { 1 }], stop.Token));
    }
    [Fact]
    public async Task WaitModeLeavesSendOpenAndCompletesWhenHesCloses()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions { TcpSourcePort = 0 }));
        var sending = sender.SendAsync("one", IPAddress.IPv6Loopback, $"[::1]:{port}", port, [[1, 2, 3]],
            stop.Token, waitForPeerCloseSeconds: 15);
        using var peer = await listener.AcceptTcpClientAsync(stop.Token);
        var bytes = new byte[3];
        await peer.GetStream().ReadExactlyAsync(bytes, stop.Token);
        Assert.Equal(new byte[] { 1, 2, 3 }, bytes);
        Assert.Equal(1, sender.Connections.Active);
        Assert.Equal(1, sender.Connections.Opened);
        Assert.False(sending.IsCompleted);

        using var probe = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
        probe.CancelAfter(100);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            int read = await peer.GetStream().ReadAsync(new byte[1], probe.Token);
            Assert.Fail($"MAYA ended its send stream early (read returned {read}).");
        });
        await peer.GetStream().WriteAsync(new byte[] { 7 }, stop.Token);
        peer.Client.Shutdown(SocketShutdown.Send);
        var result = await sending;

        Assert.Equal(new PushDeliveryResult(1, 0), result);
        Assert.Equal(0, sender.Connections.Active);
        Assert.Equal(0, sender.Connections.Connecting);
        Assert.Equal(1, sender.Connections.PeerClosed);
        Assert.Equal(0, sender.Connections.WaitExpired);
        Assert.Equal(1, sender.Connections.PeakActive);
    }

    [Fact]
    public async Task PeerWaitTimeoutClosesLocallyWithoutResendingWrittenPayload()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions { TcpSourcePort = 0 }));
        var sending = sender.SendAsync("one", IPAddress.IPv6Loopback, $"[::1]:{port}", port, [[1]],
            stop.Token, waitForPeerCloseSeconds: 1);
        using var peer = await listener.AcceptTcpClientAsync(stop.Token);
        using var received = new MemoryStream();
        await peer.GetStream().CopyToAsync(received, stop.Token);
        var result = await sending;

        Assert.Equal(new byte[] { 1 }, received.ToArray());
        Assert.Equal(new PushDeliveryResult(1, 0), result);
        Assert.Equal(1, sender.Connections.WaitExpired);
        Assert.Equal(0, sender.Connections.PeerClosed);
        Assert.Equal(0, sender.Connections.Active);
        Assert.Equal(1, sender.Connections.Opened);
    }

    [Fact]
    public async Task CancellationDuringPeerWaitPreservesWrittenCountAndReleasesSocket()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var stop = new CancellationTokenSource();
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions { TcpSourcePort = 0 }));
        var sending = sender.SendAsync("one", IPAddress.IPv6Loopback, $"[::1]:{port}", port, [[1]],
            stop.Token, waitForPeerCloseSeconds: 15);
        using var peer = await listener.AcceptTcpClientAsync(timeout.Token);
        await peer.GetStream().ReadExactlyAsync(new byte[1], timeout.Token);
        stop.Cancel();
        var error = await Assert.ThrowsAsync<PushCanceledException>(() => sending);

        Assert.Equal(1, error.Sent);
        Assert.Equal(0, error.Failed);
        Assert.Equal(0, sender.Connections.Active);
        Assert.Equal(0, sender.Connections.WaitExpired);
        Assert.Equal(0, await peer.GetStream().ReadAsync(new byte[1], timeout.Token));
    }

}
