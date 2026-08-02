using System.Net;
using ManyMeterSimulator.BadComm;

namespace ManyMeterSimulator.Diagnostics;

public sealed class ConnectionState
{
    private long _lastActivityTicksUtc = DateTimeOffset.UtcNow.UtcTicks;

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

    public required IPAddress MeterId { get; init; }

    public required IPEndPoint RemoteEndPoint { get; init; }

    /// <summary>Linked to the service's shutdown token; also cancelled by the idle sweep to force-close a stale session.</summary>
    public required CancellationTokenSource SessionCts { get; init; }

    public DateTimeOffset ConnectedAtUtc { get; } = DateTimeOffset.UtcNow;

    public DateTimeOffset LastActivityUtc => new(Interlocked.Read(ref _lastActivityTicksUtc), TimeSpan.Zero);

    /// <summary>Set just before the idle sweep cancels the session, so the session loop can log the right reason.</summary>
    public bool IdleTimedOut { get; private set; }

    public void Touch() => Interlocked.Exchange(ref _lastActivityTicksUtc, DateTimeOffset.UtcNow.UtcTicks);

    public void CancelDueToIdleTimeout()
    {
        IdleTimedOut = true;
        SessionCts.Cancel();
    }
}
