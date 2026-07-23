using System.Net;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.MqttBridge;

/// <summary>
/// Framing-only stand-in for the real brain (<see cref="BrainMeterSimBridge"/>). No brain,
/// no DLMS — just simulates round-trip latency and echoes the request frame back, so the
/// framing/session/registry layers are testable end-to-end without the brain. Selectable via
/// config; the brain bridge is the default.
/// </summary>
public sealed class SimulatedMeterSimBridge : IMeterSimBridge
{
    private readonly SimulatedBridgeOptions _options;

    public SimulatedMeterSimBridge(IOptions<SimulatedBridgeOptions> options)
    {
        _options = options.Value;
    }

    public async Task<byte[]> ExchangeAsync(IPAddress meterId, byte[] requestFrame, CancellationToken cancellationToken)
    {
        await Task.Delay(_options.RoundTripDelayMs, cancellationToken);
        return requestFrame;
    }
}
