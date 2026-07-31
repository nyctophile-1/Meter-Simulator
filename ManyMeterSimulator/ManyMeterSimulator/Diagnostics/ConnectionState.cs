using System.Net;
using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Diagnostics;

public sealed class ConnectionState
{
    private long _lastActivityTicksUtc = DateTimeOffset.UtcNow.UtcTicks;
    private long _exchangeCount;

    /// <summary>Which meter this session belongs to — NIC-agnostic, and the registry's key.</summary>
    public required MeterRef Meter { get; init; }

    /// <summary>
    /// TCP only: the meter's own IPv6 (the socket's local address) and the HES endpoint that dialled
    /// it. Null on connectionless NICs, where there is no peer to name — the meter is identified by
    /// <see cref="Meter"/> alone.
    /// </summary>
    public IPAddress? MeterAddress { get; init; }

    public IPEndPoint? RemoteEndPoint { get; init; }

    /// <summary>
    /// True for a connectionless NIC's session, which exists only because a message arrived and has
    /// no owning loop to clean up after it.
    ///
    /// On TCP the session loop unregisters in its <c>finally</c> when the socket closes. An MQTT
    /// session has no such moment, so the idle sweep must remove it from the registry itself —
    /// otherwise a reaped session would linger forever and permanently block that meter as
    /// "already active".
    /// </summary>
    public bool IsVirtual { get; init; }

    /// <summary>Linked to the service's shutdown token; also cancelled by the idle sweep to force-close a stale session.</summary>
    public required CancellationTokenSource SessionCts { get; init; }

    public DateTimeOffset ConnectedAtUtc { get; } = DateTimeOffset.UtcNow;

    public DateTimeOffset LastActivityUtc => new(Interlocked.Read(ref _lastActivityTicksUtc), TimeSpan.Zero);

    /// <summary>Set just before the idle sweep cancels the session, so the session loop can log the right reason.</summary>
    public bool IdleTimedOut { get; private set; }

    /// <summary>Completed request/response exchanges on this session.</summary>
    public long ExchangeCount => Interlocked.Read(ref _exchangeCount);

    /// <summary>
    /// Counts a completed exchange and returns the new total. Callers log the FIRST one louder:
    /// "this meter answered at all" is the interesting event, and every one after it is routine.
    /// </summary>
    public long RecordExchange() => Interlocked.Increment(ref _exchangeCount);

    public void Touch() => Interlocked.Exchange(ref _lastActivityTicksUtc, DateTimeOffset.UtcNow.UtcTicks);

    public void CancelDueToIdleTimeout()
    {
        IdleTimedOut = true;
        SessionCts.Cancel();
    }
}
