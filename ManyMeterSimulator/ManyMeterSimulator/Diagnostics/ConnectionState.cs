using System.Net;

namespace ManyMeterSimulator.Diagnostics;

public sealed class ConnectionState
{
    private long _lastActivityTicksUtc = DateTimeOffset.UtcNow.UtcTicks;

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
