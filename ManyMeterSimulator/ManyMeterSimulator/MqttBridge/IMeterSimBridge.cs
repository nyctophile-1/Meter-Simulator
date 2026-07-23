using System.Net;

namespace ManyMeterSimulator.MqttBridge;

/// <summary>
/// Bridges one DLMS APDU request/response exchange to meter_sim, keyed by meter IP.
/// Phase 4 will implement this over MQTT (sim_request/{ip} / sim_response/{ip});
/// for now, <see cref="SimulatedMeterSimBridge"/> stands in.
/// </summary>
public interface IMeterSimBridge
{
    Task<byte[]> ExchangeAsync(IPAddress meterId, byte[] requestPayload, CancellationToken cancellationToken);
}
