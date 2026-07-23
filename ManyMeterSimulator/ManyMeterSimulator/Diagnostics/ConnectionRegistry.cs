using System.Collections.Concurrent;
using System.Net;
using System.Linq;

namespace ManyMeterSimulator.Diagnostics;

/// <summary>
/// Tracks the single active session per meter IP. Load-bearing, not just observability:
/// enforces one concurrent TCP session per meter (real meter firmware only accepts one),
/// and is the lookup used to route MQTT responses back to the right open connection.
/// </summary>
public sealed class ConnectionRegistry
{
    private readonly ConcurrentDictionary<IPAddress, ConnectionState> _activeConnections = new();

    /// <summary>Atomically registers a session for a meter. False if one is already active.</summary>
    public bool TryRegister(IPAddress meterId, ConnectionState state) => _activeConnections.TryAdd(meterId, state);

    /// <summary>Removes the given session, but only if it's still the one on record for that meter.</summary>
    public void Unregister(IPAddress meterId, ConnectionState state)
    {
        _activeConnections.TryRemove(new KeyValuePair<IPAddress, ConnectionState>(meterId, state));
    }

    public bool TryGet(IPAddress meterId, out ConnectionState? state) => _activeConnections.TryGetValue(meterId, out state);

    public int ActiveCount => _activeConnections.Count;

    /// <summary>Point-in-time snapshot for the idle sweep to iterate without holding up accepts/registrations.</summary>
    public ConnectionState[] Snapshot() => _activeConnections.Values.ToArray();
}
