using ManyMeterSimulator.MqttBridge;
using ManyMeterSimulator.Networking.Nic;
using MeterSimulator.DLMS;

namespace ManyMeterSimulator.Brain;

/// <summary>
/// The real, in-process bridge: routes a full DLMS wrapper frame to the meter's brain session
/// and returns the brain's complete wrapper reply. Replaces <see cref="SimulatedMeterSimBridge"/>
/// as the default. A thin adapter — all per-meter state lives in <see cref="MeterSessionManager"/>.
/// </summary>
public sealed class BrainMeterSimBridge : IMeterSimBridge
{
    private readonly MeterSessionManager _sessions;
    private readonly ILogger<BrainMeterSimBridge> _logger;

    public BrainMeterSimBridge(MeterSessionManager sessions, ILogger<BrainMeterSimBridge> logger)
    {
        _sessions = sessions;
        _logger = logger;
    }

    public async Task<byte[]> ExchangeAsync(MeterRef meter, byte[] requestFrame, CancellationToken cancellationToken)
    {
        DLMSServerSession session;
        try
        {
            session = _sessions.GetOrCreate(meter);
        }
        catch (Exception ex)
        {
            // Should be unreachable on the inbound path (the NIC rejects meters with no template)
            // — but never let a build failure take down the session loop.
            _logger.LogError(ex, "Meter {Meter}: could not build brain session", meter);
            return Array.Empty<byte>();
        }

        // HandleRequest is synchronous, stateful, CPU-bound DLMS work. Offload it so the IO
        // pipeline thread isn't blocked, and serialize per session — a DLMS server session is not
        // thread-safe. Single-session-per-meter (SessionRegistry) already prevents concurrent
        // inbound use; the lock also guards against future concurrent push on the same session.
        return await Task.Run(() =>
        {
            lock (session)
            {
                return session.HandleRequest(requestFrame) ?? Array.Empty<byte>();
            }
        }, cancellationToken);
    }
}
