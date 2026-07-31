using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.MqttBridge;

/// <summary>
/// Bridges one DLMS request/response exchange to the meter brain.
///
/// The exchanged bytes are the COMPLETE DLMS-over-TCP Wrapper frame (8-byte WPDU header + APDU),
/// not just the payload: the brain is a Gurux WRAPPER server that owns wrapper parse/build and
/// reads the DLMS addresses out of that header. A NIC extracts a full frame from whatever its
/// transport delivers, hands it here, and sends back verbatim whatever this returns (the brain's
/// reply is already a complete wrapper frame).
///
/// This is THE funnel every NIC shares — TCP reads frames off a socket, the MQTT NICs unwrap them
/// out of a broker message, and below this line nothing knows the difference.
///
/// <see cref="ManyMeterSimulator.Brain.BrainMeterSimBridge"/> is the real in-process implementation;
/// <see cref="SimulatedMeterSimBridge"/> is a framing-only stand-in.
/// </summary>
public interface IMeterSimBridge
{
    Task<byte[]> ExchangeAsync(MeterRef meter, byte[] requestFrame, CancellationToken cancellationToken);
}
