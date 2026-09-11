namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// Resolves a live broker binding and opens publish-only pools for outbound push. The legacy
/// single-message method remains available on the listener connection.
///
/// <para>
/// A narrow interface rather than a dependency on the whole hosted service, so
/// <see cref="ManyMeterSimulator.Brain.PushCoordinator"/> depends only on what it uses — and can be
/// unit-tested without standing up a broker listener.
/// </para>
/// </summary>
public interface IMqttPushPublisher
{
    /// <summary>Whether a live client serves this binding (a running batch has brought its broker up).</summary>
    bool HasClient(BrokerBinding binding);

    /// <summary>
    /// Publishes one push on the binding's broker connection. False if no live client serves it, so
    /// the caller can report rather than silently drop.
    /// </summary>
    Task<bool> TryPublishPushAsync(BrokerBinding binding, NicPublish publish, int qos, CancellationToken cancellationToken);

    Task<IMqttPushPool> OpenPoolAsync(BrokerBinding binding, int publisherCount, int qos,
        int publishTimeoutSeconds, CancellationToken cancellationToken);
}
