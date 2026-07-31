using System.Buffers;
using ManyMeterSimulator.Networking.Nic;
using MQTTnet;
using MQTTnet.Protocol;

namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// One broker connection for one NIC variant: connect (trying each configured credential in turn),
/// subscribe, publish, and reconnect forever with a fixed backoff.
///
/// One client per variant rather than one per meter — the broker already multiplexes, and a real
/// deployment has far fewer gateways than meters. Per-variant rather than one global client so a
/// broker problem on one variant cannot stop the others, and so each is independently
/// enable/disable-able and independently observable.
/// </summary>
public sealed class MqttNicClient : IAsyncDisposable
{
    private readonly ILogger _logger;
    private readonly NicType _nic;
    private readonly MqttBrokerOptions _broker;
    private readonly Func<NicEnvelope, Task> _onMessage;
    private readonly IMqttClient _client;
    private readonly SemaphoreSlim _publishLock = new(1, 1);

    private IReadOnlyList<string> _topicFilters = Array.Empty<string>();
    private int _subscribeQos = 2;

    public MqttNicClient(
        ILogger logger,
        NicType nic,
        MqttBrokerOptions broker,
        Func<NicEnvelope, Task> onMessage)
    {
        _logger = logger;
        _nic = nic;
        _broker = broker;
        _onMessage = onMessage;

        _client = new MqttClientFactory().CreateMqttClient();
        _client.ApplicationMessageReceivedAsync += HandleMessageAsync;
    }

    /// <summary>Live connection state, surfaced on the dashboard — the MQTT answer to "is the listener bound?".</summary>
    public MqttConnectionStatus Status { get; private set; } = MqttConnectionStatus.Disconnected();

    /// <summary>
    /// Connects and subscribes, then keeps the connection up until cancelled. Never throws on a
    /// broker problem — it retries, because a simulator that dies when the broker blips is useless
    /// for long soak runs.
    /// </summary>
    public async Task RunAsync(IReadOnlyList<string> topicFilters, int subscribeQos, CancellationToken cancellationToken)
    {
        _topicFilters = topicFilters;
        _subscribeQos = subscribeQos;

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (!_client.IsConnected)
                {
                    await ConnectAndSubscribeAsync(cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Status = MqttConnectionStatus.Failed(ex.Message, Status.Attempts + 1);
                _logger.LogWarning(
                    "{Nic}: broker {Host}:{Port} unreachable ({Message}); retrying in {Delay}s",
                    _nic, _broker.Host, _broker.Port, ex.Message, _broker.ReconnectDelaySeconds);
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(_broker.ReconnectDelaySeconds), cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        if (_client.IsConnected)
        {
            try
            {
                await _client.DisconnectAsync(cancellationToken: CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "{Nic}: error during clean disconnect", _nic);
            }
        }

        Status = MqttConnectionStatus.Disconnected();
    }

    private async Task ConnectAndSubscribeAsync(CancellationToken cancellationToken)
    {
        List<MqttCredential> candidates = _broker.Credentials.Count > 0
            ? _broker.Credentials
            : new List<MqttCredential> { new() { Name = "anonymous" } };

        Exception? lastError = null;

        // Try each credential in turn. The configured order matters: the meter-side credential
        // should be first, since that is the role we are impersonating (virtual_nics.md §14.5).
        foreach (MqttCredential credential in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();

            MqttClientOptions options = BuildOptions(credential);
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(_broker.ConnectTimeoutSeconds));

                await _client.ConnectAsync(options, timeout.Token);

                await SubscribeAsync(cancellationToken);

                Status = MqttConnectionStatus.Connected(credential.Name, _topicFilters.Count);
                _logger.LogInformation(
                    "{Nic}: connected to {Host}:{Port} as '{Credential}' ({Username}); subscribed to {Filters}",
                    _nic, _broker.Host, _broker.Port, credential.Name, credential.Username,
                    string.Join(", ", _topicFilters));
                return;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                lastError = ex;
                _logger.LogWarning(
                    "{Nic}: credential '{Credential}' rejected by {Host}:{Port} ({Message})",
                    _nic, credential.Name, _broker.Host, _broker.Port, ex.Message);
            }
        }

        throw lastError ?? new InvalidOperationException("No credentials configured.");
    }

    private MqttClientOptions BuildOptions(MqttCredential credential)
    {
        MqttClientOptionsBuilder builder = new MqttClientOptionsBuilder()
            // A disposable id, matching HES's own behaviour (fresh GUID + clean session), so
            // reconnects never collide with a lingering server-side session.
            .WithClientId($"{_broker.ClientIdPrefix}-{_nic}-{Guid.NewGuid():N}")
            .WithTcpServer(_broker.Host, _broker.Port)
            .WithCleanSession(true)
            .WithTlsOptions(o => o.UseTls(_broker.UseTls));

        if (!string.IsNullOrEmpty(credential.Username))
        {
            builder = builder.WithCredentials(credential.Username, credential.Password);
        }

        return builder.Build();
    }

    private async Task SubscribeAsync(CancellationToken cancellationToken)
    {
        if (_topicFilters.Count == 0)
        {
            return;
        }

        var subscribe = new MqttClientSubscribeOptionsBuilder();
        foreach (string filter in _topicFilters)
        {
            subscribe = subscribe.WithTopicFilter(f => f
                .WithTopic(filter)
                .WithQualityOfServiceLevel((MqttQualityOfServiceLevel)_subscribeQos));
        }

        await _client.SubscribeAsync(subscribe.Build(), cancellationToken);
    }

    /// <summary>
    /// Publishes one message. Serialized, since MQTTnet's client is not safe for concurrent publish.
    ///
    /// The broker's acknowledgement is checked rather than discarded: at QoS 1/2 a failure here
    /// means the broker never took the message, which is a completely different problem from the
    /// broker taking it and no one being subscribed. Without this the two are indistinguishable
    /// from our side.
    /// </summary>
    public async Task PublishAsync(string topic, byte[] payload, int qos, CancellationToken cancellationToken)
    {
        MqttApplicationMessage message = new MqttApplicationMessageBuilder()
            .WithTopic(topic)
            .WithPayload(payload)
            .WithQualityOfServiceLevel((MqttQualityOfServiceLevel)qos)
            .Build();

        await _publishLock.WaitAsync(cancellationToken);
        MqttClientPublishResult result;
        try
        {
            result = await _client.PublishAsync(message, cancellationToken);
        }
        finally
        {
            _publishLock.Release();
        }

        if (!result.IsSuccess)
        {
            _logger.LogWarning(
                "{Nic}: broker REJECTED publish to {Topic} — {ReasonCode} {ReasonString}",
                _nic, topic, result.ReasonCode, result.ReasonString);
        }
        else
        {
            _logger.LogDebug("{Nic}: broker accepted publish to {Topic} ({ReasonCode})", _nic, topic, result.ReasonCode);
        }
    }

    private async Task HandleMessageAsync(MqttApplicationMessageReceivedEventArgs args)
    {
        // Keep this callback short: MQTTnet delivers on its own receive path, so anything slow here
        // stalls every meter's traffic on this connection, not just this message's.
        var envelope = new NicEnvelope(
            args.ApplicationMessage.Topic,
            args.ApplicationMessage.Payload.ToArray(),
            DateTimeOffset.UtcNow);

        try
        {
            await _onMessage(envelope);
        }
        catch (Exception ex)
        {
            // A codec or handler fault must never tear down the subscription for every other meter.
            _logger.LogError(ex, "{Nic}: error handling message on {Topic}", _nic, envelope.Topic);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _client.ApplicationMessageReceivedAsync -= HandleMessageAsync;
        _client.Dispose();
        _publishLock.Dispose();
        await ValueTask.CompletedTask;
    }
}

/// <summary>Point-in-time broker connection state for the dashboard.</summary>
public readonly record struct MqttConnectionStatus(
    bool IsConnected,
    string? CredentialName,
    int SubscribedFilters,
    string? LastError,
    int Attempts,
    DateTimeOffset AsOfUtc)
{
    public static MqttConnectionStatus Disconnected() =>
        new(false, null, 0, null, 0, DateTimeOffset.UtcNow);

    public static MqttConnectionStatus Connected(string credentialName, int filters) =>
        new(true, credentialName, filters, null, 0, DateTimeOffset.UtcNow);

    public static MqttConnectionStatus Failed(string error, int attempts) =>
        new(false, null, 0, error, attempts, DateTimeOffset.UtcNow);
}
