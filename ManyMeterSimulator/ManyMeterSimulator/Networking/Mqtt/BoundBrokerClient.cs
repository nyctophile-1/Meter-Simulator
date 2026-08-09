using ManyMeterSimulator.Networking.Registry;

namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// One live broker connection and everything that belongs to it: the binding it serves, its own
/// codec instance (fragment state must not be shared between brokers), and the cancellation that
/// stops it when the binding goes away.
///
/// <para>
/// This is the object a <see cref="NicWorkItem"/> carries so its reply can be published back on the
/// exact connection the request arrived on.
/// </para>
/// </summary>
public sealed class BoundBrokerClient : IAsyncDisposable
{
    private readonly CancellationTokenSource _stop;

    public BoundBrokerClient(
        BrokerBinding binding,
        BrokerEndpoint endpoint,
        MqttNicClient client,
        INicCodec codec,
        MqttNicOptions options,
        CancellationTokenSource stop)
    {
        Binding = binding;
        Endpoint = endpoint;
        Client = client;
        Codec = codec;
        Options = options;
        _stop = stop;
    }

    public BrokerBinding Binding { get; }

    /// <summary>The registry entry as it was when this client started — see <see cref="Matches"/>.</summary>
    public BrokerEndpoint Endpoint { get; }

    public MqttNicClient Client { get; }

    /// <summary>This binding's own codec instance. Never shared (network_registry.md §5.4).</summary>
    public INicCodec Codec { get; }

    public MqttNicOptions Options { get; }

    /// <summary>The client's run loop, awaited on shutdown so the disconnect completes.</summary>
    public Task? Runner { get; set; }

    /// <summary>
    /// Whether this live client still reflects the registry row it was started from. An edited
    /// broker (rotated password, moved host) keeps its key, so the binding looks unchanged while
    /// the connection details underneath it are stale — without this the reconcile pass would see
    /// "already running" and the edit would never take effect.
    /// </summary>
    public bool Matches(BrokerEndpoint current) =>
        Endpoint.Host == current.Host
        && Endpoint.Port == current.Port
        && Endpoint.UseTls == current.UseTls
        && Endpoint.Username == current.Username
        && Endpoint.Password == current.Password;

    public void RequestStop()
    {
        if (!_stop.IsCancellationRequested)
        {
            _stop.Cancel();
        }
    }

    public async ValueTask DisposeAsync()
    {
        RequestStop();

        if (Runner is not null)
        {
            try
            {
                await Runner;
            }
            catch (OperationCanceledException)
            {
                // Expected: this is how the run loop ends.
            }
        }

        await Client.DisposeAsync();
        _stop.Dispose();
    }
}
