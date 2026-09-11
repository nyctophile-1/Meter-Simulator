using System.Threading.Channels;
using MQTTnet;
using MQTTnet.Protocol;

namespace ManyMeterSimulator.Networking.Mqtt;

public readonly record struct MqttPushDelivery(int Sent, int Failed, string? Error = null);

public interface IMqttPushPool : IAsyncDisposable
{
    bool IsConnected { get; }
    Task<MqttPushDelivery> PublishMeterAsync(IReadOnlyList<NicPublish> messages, CancellationToken cancellationToken);
}

/// <summary>A publish-only connection. Pool leases keep one meter's fragments on one connection.</summary>
public interface IMqttPushConnection : IAsyncDisposable
{
    bool IsConnected { get; }
    Task ConnectAsync(CancellationToken cancellationToken);
    Task<bool> PublishAsync(NicPublish message, int qos, CancellationToken cancellationToken);
}

/// <summary>
/// Connections are opened before sending and reused for the whole run. No subscriptions, retries,
/// unbounded message queue, or per-message logging. One outstanding publish per leased connection.
/// </summary>
public sealed class MqttPushPool : IMqttPushPool
{
    private readonly IMqttPushConnection[] _connections;
    private readonly Channel<IMqttPushConnection> _available;
    private readonly int _qos;
    private readonly TimeSpan _publishTimeout;
    private int _disposed;

    private MqttPushPool(IMqttPushConnection[] connections, int qos, TimeSpan publishTimeout)
    {
        _connections = connections;
        _qos = qos;
        _publishTimeout = publishTimeout;
        _available = Channel.CreateBounded<IMqttPushConnection>(connections.Length);
        foreach (var connection in connections) _available.Writer.TryWrite(connection);
    }

    public bool IsConnected => _disposed == 0 && _connections.All(c => c.IsConnected);

    public static Task<MqttPushPool> ConnectAsync(MqttBrokerOptions options, int count, int qos,
        int publishTimeoutSeconds, CancellationToken cancellationToken)
    {
        if (qos is < 0 or > 2) throw new ArgumentOutOfRangeException(nameof(qos));
        if (publishTimeoutSeconds is < 1 or > 3600) throw new ArgumentOutOfRangeException(nameof(publishTimeoutSeconds));
        return OpenAsync(Enumerable.Range(0, ValidateCount(count))
            .Select(_ => (IMqttPushConnection)new Connection(options)).ToArray(), qos,
            TimeSpan.FromSeconds(publishTimeoutSeconds), cancellationToken);
    }

    public static async Task<MqttPushPool> OpenAsync(IMqttPushConnection[] connections, int qos,
        TimeSpan publishTimeout, CancellationToken cancellationToken)
    {
        ValidateCount(connections.Length);
        if (qos is < 0 or > 2) throw new ArgumentOutOfRangeException(nameof(qos));
        if (publishTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(publishTimeout));
        var pool = new MqttPushPool(connections, qos, publishTimeout);
        try
        {
            await Task.WhenAll(connections.Select(c => c.ConnectAsync(cancellationToken)));
            cancellationToken.ThrowIfCancellationRequested();
            return pool;
        }
        catch
        {
            await pool.DisposeAsync();
            throw;
        }
    }

    private static int ValidateCount(int count) => count is >= 1 and <= 64
        ? count : throw new ArgumentOutOfRangeException(nameof(count), "Use 1 to 64 publishing connections per broker binding.");

    public async Task<MqttPushDelivery> PublishMeterAsync(IReadOnlyList<NicPublish> messages, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        var connection = await _available.Reader.ReadAsync(cancellationToken);
        int sent = 0, failed = 0;
        string? error = null;
        try
        {
            foreach (NicPublish message in messages)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(_publishTimeout);
                try
                {
                    if (!connection.IsConnected) throw new IOException("Publishing connection disconnected; prepare a new run to reconnect.");
                    if (await connection.PublishAsync(message, _qos, timeout.Token)) sent++;
                    else
                    {
                        failed++;
                        error ??= "Broker rejected a publish.";
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    // Do not replay an ambiguously delivered QoS packet. Count the unsent remainder.
                    return new MqttPushDelivery(sent, messages.Count - sent,
                        ex is OperationCanceledException ? "Publish timed out; delivery is unconfirmed." : ex.Message);
                }
            }
            return new MqttPushDelivery(sent, failed, error);
        }
        finally { _available.Writer.TryWrite(connection); }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _available.Writer.TryComplete();
        await Task.WhenAll(_connections.Select(async c => await c.DisposeAsync()));
    }

    private sealed class Connection(MqttBrokerOptions options) : IMqttPushConnection
    {
        private readonly IMqttClient _client = new MqttClientFactory().CreateMqttClient();
        public bool IsConnected => _client.IsConnected;

        public async Task ConnectAsync(CancellationToken cancellationToken)
        {
            Exception? lastError = null;
            var credentials = options.Credentials.Count > 0 ? options.Credentials : [new MqttCredential()];
            foreach (var credential in credentials)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var builder = new MqttClientOptionsBuilder()
                    .WithClientId($"{options.ClientIdPrefix}-push-{Guid.NewGuid():N}")
                    .WithTcpServer(options.Host, options.Port)
                    .WithCleanSession(true)
                    .WithTlsOptions(o => o.UseTls(options.UseTls));
                if (!string.IsNullOrEmpty(credential.Username)) builder.WithCredentials(credential.Username, credential.Password);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, options.ConnectTimeoutSeconds)));
                try
                {
                    var result = await _client.ConnectAsync(builder.Build(), timeout.Token);
                    if (result.ResultCode != MqttClientConnectResultCode.Success)
                        throw new IOException($"Broker refused the connection: {result.ResultCode}");
                    return;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception ex) { lastError = ex; }
            }
            throw new IOException("Could not connect an MQTT push publisher.", lastError);
        }

        public async Task<bool> PublishAsync(NicPublish message, int qos, CancellationToken cancellationToken)
        {
            var result = await _client.PublishAsync(new MqttApplicationMessage
            {
                Topic = message.Topic,
                PayloadSegment = message.Payload,
                QualityOfServiceLevel = (MqttQualityOfServiceLevel)qos,
                Retain = false,
            }, cancellationToken);
            return result.IsSuccess;
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                if (_client.IsConnected) await _client.DisconnectAsync(cancellationToken: timeout.Token);
            }
            catch { /* Disposal must still release the socket after failure/cancellation. */ }
            finally { _client.Dispose(); }
        }
    }
}
