using System.Net;
using System.Net.Sockets;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Push;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public class TcpHeldConnectionTests
{
    [Theory]
    [InlineData("peer-close")]
    [InlineData("deadline")]
    [InlineData("stop")]
    public async Task SameMeterWaitsAcrossRunsWhileOtherMetersContinue(string completion)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions { TcpSourcePort = 0 }));
        await using var firstRun = new TcpPushConnectionGroup();
        await using var secondRun = new TcpPushConnectionGroup();

        await sender.SendAsync("one", IPAddress.IPv6Loopback, "::1", port, [[1]], timeout.Token,
            waitForPeerCloseSeconds: completion == "deadline" ? 1 : 15, connections: firstRun);
        using var first = await listener.AcceptTcpClientAsync(timeout.Token);
        var firstStream = first.GetStream();
        await firstStream.ReadExactlyAsync(new byte[1], timeout.Token);

        using var cancelledWait = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
        var cancelled = sender.SendAsync("one", IPAddress.IPv6Loopback, "::1", port, [[2]], cancelledWait.Token);
        Assert.False(cancelled.IsCompleted);
        cancelledWait.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);

        var sameMeter = sender.SendAsync("one", IPAddress.IPv6Loopback, "::1", port, [[3]], timeout.Token,
            waitForPeerCloseSeconds: 15, connections: secondRun);
        Assert.False(sameMeter.IsCompleted);
        Assert.Equal(1, sender.Connections.Opened);

        Assert.Equal(new PushDeliveryResult(1, 0),
            await sender.SendAsync("other", IPAddress.IPv6Loopback, "::1", port, [[4]], timeout.Token));
        using var other = await listener.AcceptTcpClientAsync(timeout.Token);
        var value = new byte[1];
        await other.GetStream().ReadExactlyAsync(value, timeout.Token);
        Assert.Equal(4, value[0]);

        if (completion == "peer-close")
        {
            first.Client.Shutdown(SocketShutdown.Send);
        }
        else if (completion == "stop")
        {
            await firstRun.DisposeAsync();
        }

        Assert.Equal(new PushDeliveryResult(1, 0), await sameMeter);
        using var next = await listener.AcceptTcpClientAsync(timeout.Token);
        await next.GetStream().ReadExactlyAsync(value, timeout.Token);
        Assert.Equal(3, value[0]);
        Assert.Equal(0, await firstStream.ReadAsync(new byte[1], timeout.Token));
        Assert.Equal(1, sender.Connections.Active);
        Assert.Equal(0, sender.Connections.ConnectFailures);

        next.Client.Shutdown(SocketShutdown.Send);
        await secondRun.DrainAsync(timeout.Token);
        Assert.Equal(0, sender.Connections.Active);
    }

    [Fact]
    public async Task CancellingInlineHoldReleasesMeterWithoutLosingItsWrittenCount()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions { TcpSourcePort = 0 }));

        var sending = sender.SendAsync("one", IPAddress.IPv6Loopback, "::1", port, [[1]], stop.Token,
            waitForPeerCloseSeconds: 15);
        using var first = await listener.AcceptTcpClientAsync(timeout.Token);
        await first.GetStream().ReadExactlyAsync(new byte[1], timeout.Token);
        var next = sender.SendAsync("one", IPAddress.IPv6Loopback, "::1", port, [[2]], timeout.Token);
        Assert.False(next.IsCompleted);

        stop.Cancel();
        await Assert.ThrowsAsync<PushCanceledException>(() => sending);
        Assert.Equal(new PushDeliveryResult(1, 0), await next);
        using var second = await listener.AcceptTcpClientAsync(timeout.Token);
        Assert.Equal(2, sender.Connections.PayloadsWritten);
        Assert.Equal(0, sender.Connections.Active);
    }

    [Fact]
    public async Task FailedConnectReleasesMeterForNextPush()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions { TcpSourcePort = 0 }));

        Assert.Equal(1, (await sender.SendAsync("one", IPAddress.IPv6Loopback, "::1", port, [[1]], timeout.Token)).Failed);

        listener.Start();
        port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Assert.Equal(1, (await sender.SendAsync("one", IPAddress.IPv6Loopback, "::1", port, [[2]], timeout.Token)).Sent);
        using var next = await listener.AcceptTcpClientAsync(timeout.Token);
        Assert.Equal(0, sender.Connections.Active);
    }

    [Fact]
    public async Task WrittenPacketsReleaseWorkersWhileStopClosesEveryHeldSocket()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions { TcpSourcePort = 0 }));
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
        var sender = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions { TcpSourcePort = 0 }));
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
    public async Task StressLoopWaitsForTheSameMetersPreviousSocketToClose()
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
        var firstStream = first.GetStream();
        await firstStream.ReadExactlyAsync(new byte[1], timeout.Token);

        using (var probe = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token))
        {
            probe.CancelAfter(100);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            {
                using var unexpected = await listener.AcceptTcpClientAsync(probe.Token);
            });
        }

        first.Client.Shutdown(SocketShutdown.Send);
        using var second = await listener.AcceptTcpClientAsync(timeout.Token);
        await second.GetStream().ReadExactlyAsync(new byte[1], timeout.Token);

        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending);
        Assert.True(run.LoopResult!.CompletedCycles >= 1);
        await firstStream.CopyToAsync(Stream.Null, timeout.Token);
        await second.GetStream().CopyToAsync(Stream.Null, timeout.Token);
    }
}
