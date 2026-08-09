using System.Net;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Diagnostics;

public sealed class ConnectionState
{
    private long _lastActivityTicksUtc = DateTimeOffset.UtcNow.UtcTicks;
    private long _exchangeCount;

    /// <summary>Which meter this session belongs to — NIC-agnostic, and the registry's key.</summary>
    ///
    /// <remarks>
    /// This replaces the <c>IPAddress MeterId</c> the TCP-only branch carried. Every NIC needs an
    /// identity and only TCP has an IP, so the index is the identity and the address is derived
    /// from it — see virtual_nics.md §4.
    /// </remarks>
    public required MeterRef Meter { get; init; }

    /// <summary>
    /// Impairment resolved once for this meter, so rule evaluation stays off the per-exchange
    /// path. <see cref="ImpairmentGeneration"/> is the classifier generation it was resolved
    /// against; when the live classifier moves past it, the session re-resolves. That is what
    /// makes a BadComm config change apply to ALREADY-OPEN connections rather than only new ones.
    /// </summary>
    public MeterImpairment Impairment { get; private set; } = MeterImpairment.Healthy;

    public int ImpairmentGeneration { get; private set; } = -1;

    public void SetImpairment(MeterImpairment impairment, int generation)
    {
        Impairment = impairment;
        ImpairmentGeneration = generation;
    }

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
