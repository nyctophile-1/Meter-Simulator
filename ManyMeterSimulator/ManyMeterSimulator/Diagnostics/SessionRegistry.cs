using System.Collections.Concurrent;
using System.Linq;
using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Diagnostics;

/// <summary>
/// Tracks the single active session per meter. Load-bearing, not just observability: enforces one
/// concurrent session per meter (real meter firmware only accepts one), and is the lookup used to
/// route a response back to the right open session.
///
/// Keyed by meter INDEX rather than by transport address, so it serves every NIC — a TCP socket and
/// a connectionless MQTT session are both "one live session for meter N". Was ConnectionRegistry.
/// </summary>
public sealed class SessionRegistry
{
    private readonly ConcurrentDictionary<long, ConnectionState> _activeSessions = new();

    /// <summary>Atomically registers a session for a meter. False if one is already active.</summary>
    public bool TryRegister(MeterRef meter, ConnectionState state) => _activeSessions.TryAdd(meter.Index, state);

    /// <summary>Removes the given session, but only if it's still the one on record for that meter.</summary>
    public void Unregister(MeterRef meter, ConnectionState state)
    {
        _activeSessions.TryRemove(new KeyValuePair<long, ConnectionState>(meter.Index, state));
    }

    public bool TryGet(MeterRef meter, out ConnectionState? state) => _activeSessions.TryGetValue(meter.Index, out state);

    public int ActiveCount => _activeSessions.Count;

    /// <summary>Live sessions on one NIC. O(n) — for the periodic summary, not the hot path.</summary>
    public int ActiveCountFor(NicType nic)
    {
        int count = 0;
        foreach (ConnectionState state in _activeSessions.Values)
        {
            if (state.Meter.Nic == nic)
            {
                count++;
            }
        }

        return count;
    }

    /// <summary>Point-in-time snapshot for the idle sweep to iterate without holding up accepts/registrations.</summary>
    public ConnectionState[] Snapshot() => _activeSessions.Values.ToArray();
}
