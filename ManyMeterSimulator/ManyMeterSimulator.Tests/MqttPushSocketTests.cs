using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ManyMeterSimulator.Networking.Mqtt;

namespace ManyMeterSimulator.Tests;

/// <summary>Real MQTTnet clients against a loopback-only MQTT fixture; no configured broker is used.</summary>
public class MqttPushSocketTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task PoolUsesRealConnectionsAndQosHandshakesWithoutSubscribing(int qos)
    {
        await using var broker = new LoopbackBroker();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var pool = await MqttPushPool.ConnectAsync(new MqttBrokerOptions
        { Host = "127.0.0.1", Port = broker.Port, ConnectTimeoutSeconds = 2 }, 4, qos, 3, timeout.Token);
        Assert.True(pool.IsConnected);
        Assert.Equal(4, broker.Connections);
        Assert.Empty(broker.Received);
        var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(i => pool.PublishMeterAsync(
            [new NicPublish($"bench/{i}", [1, 2, 3]), new NicPublish($"bench/{i}", [4, 5, 6])], timeout.Token)));
        Assert.Equal(40, results.Sum(r => r.Sent));
        // QoS 0 completes a client socket write, so wait for the fixture to observe those bytes.
        while (broker.Received.Count < 40) await Task.Delay(5, timeout.Token);
        Assert.Equal(0, broker.Subscriptions);
        Assert.All(broker.Received, packet => Assert.Equal(qos, packet.Qos));
        foreach (var meter in broker.Received.GroupBy(p => p.Topic))
        {
            Assert.Equal(2, meter.Count());
            Assert.Single(meter.Select(p => p.Connection).Distinct());
            Assert.Equal(new byte[] { 1, 4 }, meter.Select(p => p.FirstByte));
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task BrokerNegativeAcknowledgementIsReportedAsFailed(int qos)
    {
        await using var broker = new LoopbackBroker { Reject = true };
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var pool = await MqttPushPool.ConnectAsync(new MqttBrokerOptions
        { Host = "127.0.0.1", Port = broker.Port, ConnectTimeoutSeconds = 2 }, 1, qos, 3, timeout.Token);
        var result = await pool.PublishMeterAsync([new NicPublish("rejected", [1])], timeout.Token);
        Assert.Equal(0, result.Sent);
        Assert.Equal(1, result.Failed);
        Assert.Contains("rejected", result.Error);
    }

    private sealed class LoopbackBroker : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly ConcurrentBag<TcpClient> _clients = [];
        private readonly ConcurrentBag<Task> _handlers = [];
        private readonly Task _accept;
        public int Connections;
        public int Subscriptions;
        public bool Reject { get; init; }
        public ConcurrentQueue<(int Connection, string Topic, int Qos, byte FirstByte)> Received { get; } = new();
        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public LoopbackBroker()
        {
            _listener.Start();
            _accept = AcceptAsync();
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                    _clients.Add(client);
                    _handlers.Add(HandleAsync(client, Interlocked.Increment(ref Connections)));
                }
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        }

        private async Task HandleAsync(TcpClient client, int connection)
        {
            using var stream = client.GetStream();
            bool v5 = true;
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var header = new byte[1];
                    if (await stream.ReadAsync(header, _stop.Token) == 0) return;
                    byte fixedHeader = header[0];
                    int length = 0, multiplier = 1, digit;
                    do
                    {
                        await stream.ReadExactlyAsync(header.AsMemory(), _stop.Token);
                        digit = header[0];
                        length += (digit & 127) * multiplier;
                        multiplier *= 128;
                    } while ((digit & 128) != 0);
                    var body = new byte[length];
                    await stream.ReadExactlyAsync(body.AsMemory(), _stop.Token);
                    switch (fixedHeader >> 4)
                    {
                        case 1: // CONNECT
                            v5 = body[6] == 5;
                            await stream.WriteAsync(v5 ? new byte[] { 0x20, 3, 0, 0, 0 } : new byte[] { 0x20, 2, 0, 0 }, _stop.Token);
                            break;
                        case 3: // PUBLISH
                            int qos = (fixedHeader >> 1) & 3;
                            int topicLength = (body[0] << 8) | body[1];
                            string topic = System.Text.Encoding.UTF8.GetString(body, 2, topicLength);
                            int offset = 2 + topicLength;
                            byte idHigh = 0, idLow = 0;
                            if (qos > 0) { idHigh = body[offset++]; idLow = body[offset++]; }
                            if (v5)
                            {
                                int properties = ReadVariableInteger(body, ref offset);
                                offset += properties;
                            }
                            Received.Enqueue((connection, topic, qos, body[offset]));
                            if (qos > 0)
                            {
                                byte ack = qos == 1 ? (byte)0x40 : (byte)0x50;
                                await stream.WriteAsync(Reject
                                    ? new byte[] { ack, 4, idHigh, idLow, 0x87, 0 }
                                    : new byte[] { ack, 2, idHigh, idLow }, _stop.Token);
                            }
                            break;
                        case 6: // PUBREL -> PUBCOMP
                            await stream.WriteAsync(new byte[] { 0x70, 2, body[0], body[1] }, _stop.Token);
                            break;
                        case 8:
                            Interlocked.Increment(ref Subscriptions);
                            throw new InvalidOperationException("Push publisher unexpectedly subscribed.");
                        case 12: // PINGREQ
                            await stream.WriteAsync(new byte[] { 0xD0, 0 }, _stop.Token);
                            break;
                        case 14: return; // DISCONNECT
                        default: throw new InvalidOperationException($"Unexpected MQTT packet {fixedHeader:X2}.");
                    }
                }
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
            catch (IOException) when (_stop.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (_stop.IsCancellationRequested) { }
        }

        private static int ReadVariableInteger(byte[] bytes, ref int offset)
        {
            int value = 0, multiplier = 1;
            byte digit;
            do { digit = bytes[offset++]; value += (digit & 127) * multiplier; multiplier *= 128; }
            while ((digit & 128) != 0);
            return value;
        }

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel();
            _listener.Stop();
            await _accept;
            foreach (var client in _clients) client.Dispose();
            try { await Task.WhenAll(_handlers); }
            finally { _stop.Dispose(); }
        }
    }
}
