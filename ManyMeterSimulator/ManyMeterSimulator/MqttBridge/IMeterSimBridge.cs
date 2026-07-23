using System.Net;

namespace ManyMeterSimulator.MqttBridge;

/// <summary>
/// Bridges one DLMS request/response exchange to the meter brain, keyed by meter IP.
///
/// The exchanged bytes are the COMPLETE DLMS-over-TCP Wrapper frame (8-byte WPDU header +
/// APDU), not just the payload: the brain is a Gurux WRAPPER server that owns wrapper
/// parse/build and reads the DLMS addresses out of that header. The listener reads a full
/// frame off the wire, hands it here, and writes back verbatim whatever this returns
/// (the brain's reply is already a complete wrapper frame).
///
/// <see cref="BrainMeterSimBridge"/> is the real in-process implementation;
/// <see cref="SimulatedMeterSimBridge"/> is a framing-only stand-in.
/// </summary>
public interface IMeterSimBridge
{
    Task<byte[]> ExchangeAsync(IPAddress meterId, byte[] requestFrame, CancellationToken cancellationToken);
}
