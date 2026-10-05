using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using Microsoft.Extensions.Logging.Abstractions;
using MQTTnet.Exceptions;

namespace ManyMeterSimulator.Tests;

public sealed class MqttNicClientTests
{
    [Fact]
    public async Task ConcurrentQosZeroRepliesHaveIntactPayloadsAndNeedNoAcknowledgements()
    {
        await using var peer = new MqttPeer();
        await peer.ConnectAsync();

        int qos = new MqttNicOptions().PublishQos;
        Task<bool>[] sends = Enumerable.Range(0, 256)
            .Select(i => peer.Client.PublishAsync($"reply/{i}", Encoding.UTF8.GetBytes($"payload-{i}"), qos, peer.Token))
            .ToArray();

        var topics = new HashSet<string>();

        for (int i = 0; i < sends.Length; i++)
        {
            Packet packet = await peer.ReadAsync();
            Assert.Equal(0x30, packet.Header);

            int topicLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Body);
            string topic = Encoding.UTF8.GetString(packet.Body, 2, topicLength);
            Assert.Equal(0, packet.Body[2 + topicLength]); // MQTT 5 property length.
            Assert.Equal($"payload-{topic[6..]}", Encoding.UTF8.GetString(packet.Body, 3 + topicLength, packet.Body.Length - 3 - topicLength));
            Assert.True(topics.Add(topic));
        }

        Assert.All(await Task.WhenAll(sends).WaitAsync(peer.Token), sent => Assert.True(sent));
    }

    [Fact]
    public async Task PipelineIsBoundedAndQueuedCancellationDoesNotLeakSlots()
    {
        await using var peer = new MqttPeer(maxConcurrentPublishes: 2);
        await peer.ConnectAsync();

        Task<bool> first = peer.Client.PublishAsync("reply/first", [1], 1, peer.Token);
        Task<bool> second = peer.Client.PublishAsync("reply/second", [2], 1, peer.Token);
        Packet firstPacket = await peer.ReadAsync();
        Packet secondPacket = await peer.ReadAsync();
        Assert.False(first.IsCompleted);
        Assert.False(second.IsCompleted);

        using var queuedStop = CancellationTokenSource.CreateLinkedTokenSource(peer.Token);
        Task<bool> queued = peer.Client.PublishAsync("reply/queued", [3], 1, queuedStop.Token);

        using (var noPacket = new CancellationTokenSource(TimeSpan.FromMilliseconds(150)))
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => peer.ReadAsync(noPacket.Token));
        }

        queuedStop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued);

        // Complete in reverse order to check packet-identifier correlation.
        await peer.AcknowledgeAsync(secondPacket);
        Assert.True(await second.WaitAsync(peer.Token));
        Assert.False(first.IsCompleted);

        Task<bool> next = peer.Client.PublishAsync("reply/next", [4], 1, peer.Token);
        Packet nextPacket = await peer.ReadAsync();
        await peer.AcknowledgeAsync(nextPacket);
        await peer.AcknowledgeAsync(firstPacket);

        Assert.True(await next.WaitAsync(peer.Token));
        Assert.True(await first.WaitAsync(peer.Token));
    }

    [Fact]
    public async Task RejectionAndInFlightCancellationReleaseThePublishSlot()
    {
        await using var peer = new MqttPeer(maxConcurrentPublishes: 1);
        await peer.ConnectAsync();

        Task<bool> rejected = peer.Client.PublishAsync("reply/rejected", [1], 1, peer.Token);
        await peer.AcknowledgeAsync(await peer.ReadAsync(), reason: 0x87);
        Assert.False(await rejected.WaitAsync(peer.Token));

        using var stop = CancellationTokenSource.CreateLinkedTokenSource(peer.Token);
        Task<bool> canceled = peer.Client.PublishAsync("reply/canceled", [2], 1, stop.Token);
        await peer.ReadAsync();
        stop.Cancel();
        await Assert.ThrowsAsync<MqttCommunicationTimedOutException>(() => canceled);

        Task<bool> recovered = peer.Client.PublishAsync("reply/recovered", [3], 0, peer.Token);
        Assert.Equal(0x30, (await peer.ReadAsync()).Header);
        Assert.True(await recovered.WaitAsync(peer.Token));
    }

    private sealed record Packet(byte Header, byte[] Body);

    private sealed class MqttPeer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new(TimeSpan.FromSeconds(15));
        private TcpClient? _connection;
        private Task? _runner;

        public MqttPeer(int maxConcurrentPublishes = 32)
        {
            _listener.Start();

            Client = new MqttNicClient(
                NullLogger.Instance,
                NicType.MqttWirepas,
                new MqttBrokerOptions
                {
                    Host = "127.0.0.1",
                    Port = ((IPEndPoint)_listener.LocalEndpoint).Port,
                    ReconnectDelaySeconds = 1,
                },
                _ => Task.CompletedTask,
                maxConcurrentPublishes);
        }

        public MqttNicClient Client { get; }

        public CancellationToken Token => _stop.Token;

        public async Task ConnectAsync()
        {
            _runner = Client.RunAsync([], 2, Token);
            _connection = await _listener.AcceptTcpClientAsync(Token);
            _connection.NoDelay = true;

            Packet connect = await ReadAsync();
            Assert.Equal(0x10, connect.Header);
            Assert.Equal(5, connect.Body[6]);

            await _connection.GetStream().WriteAsync(new byte[] { 0x20, 3, 0, 0, 0 }, Token);

            while (!Client.Status.IsConnected)
            {
                await Task.Delay(10, Token);
            }
        }

        public async Task<Packet> ReadAsync(CancellationToken? cancellationToken = null)
        {
            CancellationToken token = cancellationToken ?? Token;
            NetworkStream stream = _connection!.GetStream();
            var single = new byte[1];
            await stream.ReadExactlyAsync(single, token);
            byte header = single[0];
            int length = 0;
            int multiplier = 1;

            do
            {
                await stream.ReadExactlyAsync(single, token);
                length += (single[0] & 127) * multiplier;
                multiplier *= 128;
            }
            while ((single[0] & 128) != 0);

            var body = new byte[length];
            await stream.ReadExactlyAsync(body, token);

            return new Packet(header, body);
        }

        public async Task AcknowledgeAsync(Packet packet, byte reason = 0)
        {
            Assert.Equal(0x32, packet.Header);
            int offset = 2 + BinaryPrimitives.ReadUInt16BigEndian(packet.Body);
            byte[] ack = [0x40, 4, packet.Body[offset], packet.Body[offset + 1], reason, 0];

            await _connection!.GetStream().WriteAsync(ack, Token);
        }

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel();

            if (_runner is not null)
            {
                await _runner.WaitAsync(TimeSpan.FromSeconds(5));
            }

            await Client.DisposeAsync();
            _connection?.Dispose();
            _listener.Stop();
            _stop.Dispose();
        }
    }
}
