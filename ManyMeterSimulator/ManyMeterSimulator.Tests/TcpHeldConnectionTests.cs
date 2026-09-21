using System.Net;
using System.Net.Sockets;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Push;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public class TcpHeldConnectionTests
{
    [Fact]
    public async Task WrittenPacketsReleaseWorkersWhileStopClosesEveryHeldSocket()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions()));
        await using var connections = new TcpPushConnectionGroup();
        var peers = new List<TcpClient>();

        try
        {
            for (int i = 0; i < 64; i++)
            {
                var result = await sender.SendAsync(i.ToString(), IPAddress.IPv6Loopback, $"[::1]:{port}", port,
                    [[1]], timeout.Token, waitForPeerCloseSeconds: 15, connections: connections);
                Assert.Equal(new PushDeliveryResult(1, 0), result);
                var peer = await listener.AcceptTcpClientAsync(timeout.Token);
                peers.Add(peer);
                await peer.GetStream().ReadExactlyAsync(new byte[1], timeout.Token);
            }

            Assert.Equal(64, sender.Connections.Active);
            Assert.Equal(64, sender.Connections.PayloadsWritten);
            using var stop = new CancellationTokenSource();
            var draining = connections.DrainAsync(stop.Token);
            Assert.False(draining.IsCompleted);
            stop.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => draining);

            Assert.Equal(0, sender.Connections.Active);
            Assert.Equal(0, sender.Connections.WaitExpired);
            foreach (var peer in peers)
            {
                Assert.Equal(0, await peer.GetStream().ReadAsync(new byte[1], timeout.Token));
            }
        }
        finally
        {
            foreach (var peer in peers)
            {
                peer.Dispose();
            }
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task BackgroundHoldEndsAtPeerCloseOrDeadline(bool peerCloses)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions()));
        await using var connections = new TcpPushConnectionGroup();
        var result = await sender.SendAsync("one", IPAddress.IPv6Loopback, $"[::1]:{port}", port,
            [[1]], timeout.Token, waitForPeerCloseSeconds: peerCloses ? 15 : 1, connections: connections);
        using var peer = await listener.AcceptTcpClientAsync(timeout.Token);
        var stream = peer.GetStream();
        await stream.ReadExactlyAsync(new byte[1], timeout.Token);
        Assert.Equal(new PushDeliveryResult(1, 0), result);

        if (peerCloses)
        {
            peer.Client.Shutdown(SocketShutdown.Send);
        }

        await connections.DrainAsync(timeout.Token);
        Assert.Equal(0, sender.Connections.Active);
        Assert.Equal(peerCloses ? 1 : 0, sender.Connections.PeerClosed);
        Assert.Equal(peerCloses ? 0 : 1, sender.Connections.WaitExpired);
        Assert.Equal(1, sender.Connections.PayloadsWritten);
        Assert.Equal(0, await stream.ReadAsync(new byte[1], timeout.Token));
    }
}

public partial class TcpStressIntegrationTests
{
    [Fact]
    public async Task StressLoopStartsNextPassWhilePreviousSocketRemainsOpen()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var fixture = new Fixture(((IPEndPoint)listener.LocalEndpoint).Port);
        await using var run = await fixture.Push.OpenTcpRunAsync(fixture.Request with
        {
            MaxConcurrency = 1,
            WaitForPeerCloseSeconds = 15
        }, stop.Token);
        var sending = run.SendLoopAsync(new());
        using var first = await listener.AcceptTcpClientAsync(timeout.Token);
        await first.GetStream().ReadExactlyAsync(new byte[1], timeout.Token);
        using var second = await listener.AcceptTcpClientAsync(timeout.Token);
        await second.GetStream().ReadExactlyAsync(new byte[1], timeout.Token);

        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending);
        Assert.True(run.LoopResult!.CompletedCycles >= 1);
        await first.GetStream().CopyToAsync(Stream.Null, timeout.Token);
        await second.GetStream().CopyToAsync(Stream.Null, timeout.Token);
    }
}
