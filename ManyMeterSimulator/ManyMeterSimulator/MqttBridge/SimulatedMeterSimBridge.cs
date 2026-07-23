using System.Net;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.MqttBridge;

/// <summary>
/// Temporary stand-in for the real MQTT bridge to meter_sim. No MQTT, no brain -
/// just simulates round-trip latency and echoes the request payload back, so the
/// framing/session/registry layers are testable end-to-end before Phase 4 exists.
/// </summary>
public sealed class SimulatedMeterSimBridge : IMeterSimBridge
{
    private readonly SimulatedBridgeOptions _options;

    public SimulatedMeterSimBridge(IOptions<SimulatedBridgeOptions> options)
    {
        _options = options.Value;
    }

    public async Task<byte[]> ExchangeAsync(IPAddress meterId, byte[] requestPayload, CancellationToken cancellationToken)
    {
        await Task.Delay(_options.RoundTripDelayMs, cancellationToken);
        return requestPayload;
    }
}
