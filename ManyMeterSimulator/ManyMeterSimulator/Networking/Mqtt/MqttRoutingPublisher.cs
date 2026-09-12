using ManyMeterSimulator.Networking.Registry;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Networking.Mqtt;

public interface IMqttRoutingPublisher
{
    Task<IMqttPushPool> OpenPoolAsync(BrokerEndpoint endpoint, CancellationToken cancellationToken);
}

public sealed class MqttRoutingPublisher(IOptions<NicsOptions> options) : IMqttRoutingPublisher
{
    public async Task<IMqttPushPool> OpenPoolAsync(BrokerEndpoint endpoint, CancellationToken cancellationToken) =>
        await MqttPushPool.ConnectAsync(options.Value.ConnectionFor(endpoint), 1, 0, 5, cancellationToken);
}
