using System.Net;
using System.Net.Sockets;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Push;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public class TcpFixedSourcePortTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RepeatedPeerClosedConnectionsKeepTheSameSourceEndpoint(bool ipv6)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var address = ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        using var listener = new TcpListener(address, 0);
        listener.Start();
        int destinationPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        int sourcePort = AvailablePort(address);
        var sender = CreateSender(sourcePort);

        for (byte cycle = 0; cycle < 4; cycle++)
        {
            var sending = sender.SendAsync("meter", address, address.ToString(), destinationPort,
                [[cycle]], timeout.Token, waitForPeerCloseSeconds: 15);
            using var peer = await listener.AcceptTcpClientAsync(timeout.Token);
            Assert.Equal(new IPEndPoint(address, sourcePort), peer.Client.RemoteEndPoint);
            var stream = peer.GetStream();
            var payload = new byte[1];
            await stream.ReadExactlyAsync(payload, timeout.Token);
            Assert.Equal(cycle, payload[0]);
            Assert.False(sending.IsCompleted);

            peer.Client.Shutdown(SocketShutdown.Send);
            Assert.Equal(new PushDeliveryResult(1, 0), await sending);
            Assert.Equal(0, await stream.ReadAsync(payload, timeout.Token));
        }

        Assert.Equal(4, sender.Connections.PeerClosed);
        Assert.Equal(4, sender.Connections.Opened);
        Assert.Equal(0, sender.Connections.ConnectFailures);
        Assert.Equal(0, sender.Connections.Active);
    }

    [Fact]
    public async Task DifferentMeterIpsCanUseTheSameSourcePortConcurrently()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int destinationPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        int sourcePort = AvailablePort(IPAddress.Loopback);
        var sender = CreateSender(sourcePort);
        var secondAddress = IPAddress.Parse("127.0.0.2");
        await using var connections = new TcpPushConnectionGroup();

        var first = await sender.SendAsync("one", IPAddress.Loopback, "127.0.0.1", destinationPort,
            [[1]], timeout.Token, waitForPeerCloseSeconds: 15, connections: connections);
        var second = await sender.SendAsync("two", secondAddress, "127.0.0.1", destinationPort,
            [[2]], timeout.Token, waitForPeerCloseSeconds: 15, connections: connections);
        Assert.Equal(new PushDeliveryResult(1, 0), first);
        Assert.Equal(new PushDeliveryResult(1, 0), second);
        using var firstPeer = await listener.AcceptTcpClientAsync(timeout.Token);
        using var secondPeer = await listener.AcceptTcpClientAsync(timeout.Token);

        Assert.Equal(new IPEndPoint(IPAddress.Loopback, sourcePort), firstPeer.Client.RemoteEndPoint);
        Assert.Equal(new IPEndPoint(secondAddress, sourcePort), secondPeer.Client.RemoteEndPoint);
        Assert.Equal(2, sender.Connections.Active);
        await firstPeer.GetStream().ReadExactlyAsync(new byte[1], timeout.Token);
        await secondPeer.GetStream().ReadExactlyAsync(new byte[1], timeout.Token);
        firstPeer.Client.Shutdown(SocketShutdown.Send);
        secondPeer.Client.Shutdown(SocketShutdown.Send);
        await connections.DrainAsync(timeout.Token);

        Assert.Equal(2, sender.Connections.PeerClosed);
        Assert.Equal(0, sender.Connections.Active);
    }

    [Fact]
    public async Task OccupiedSourcePortFailsWithoutChoosingAnotherPortAndReleasesMeter()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        int destinationPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var occupied = new TcpListener(IPAddress.IPv6Loopback, 0);
        occupied.Start();
        int sourcePort = ((IPEndPoint)occupied.LocalEndpoint).Port;
        var sender = CreateSender(sourcePort);

        var failed = await sender.SendAsync("meter", IPAddress.IPv6Loopback, "::1", destinationPort,
            [[1]], timeout.Token);
        Assert.Equal(0, failed.Sent);
        Assert.Equal(1, failed.Failed);
        Assert.Contains($"source port {sourcePort}", failed.Error);
        Assert.False(listener.Pending());
        Assert.Equal(1, sender.Connections.ConnectFailures);
        occupied.Stop();

        var sending = sender.SendAsync("meter", IPAddress.IPv6Loopback, "::1", destinationPort,
            [[2]], timeout.Token, waitForPeerCloseSeconds: 15);
        using var peer = await listener.AcceptTcpClientAsync(timeout.Token);
        Assert.Equal(sourcePort, ((IPEndPoint)peer.Client.RemoteEndPoint!).Port);
        await peer.GetStream().ReadExactlyAsync(new byte[1], timeout.Token);
        peer.Client.Shutdown(SocketShutdown.Send);

        Assert.Equal(new PushDeliveryResult(1, 0), await sending);
        Assert.Equal(0, sender.Connections.Active);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(65536)]
    public void InvalidConfiguredPortIsRejected(int sourcePort)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CreateSender(sourcePort));
    }

    private static TcpPushSender CreateSender(int sourcePort)
    {
        return new TcpPushSender(NullLogger<TcpPushSender>.Instance,
            Options.Create(new PushOptions { TcpSourcePort = sourcePort }));
    }

    private static int AvailablePort(IPAddress address)
    {
        using var listener = new TcpListener(address, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
