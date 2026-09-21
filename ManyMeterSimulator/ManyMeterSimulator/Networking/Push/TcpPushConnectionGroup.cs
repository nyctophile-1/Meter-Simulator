namespace ManyMeterSimulator.Networking.Push;

/// <summary>Owns a run's post-write sockets without occupying its send workers.</summary>
public sealed class TcpPushConnectionGroup : IAsyncDisposable
{
    private readonly object _sync = new();
    private readonly HashSet<Task> _pending = [];
    private readonly CancellationTokenSource _stop = new();
    private bool _disposed;

    internal void Track(Func<CancellationToken, Task> close)
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var task = close(_stop.Token);
            _pending.Add(task);
            _ = task.ContinueWith(completed =>
            {
                lock (_sync)
                {
                    _pending.Remove(completed);
                }
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    internal void Cancel() => _stop.Cancel();

    internal async Task DrainAsync(CancellationToken token = default)
    {
        using var cancellation = token.Register(Cancel);
        Task[] pending;
        lock (_sync)
        {
            pending = _pending.ToArray();
        }

        await Task.WhenAll(pending);
        token.ThrowIfCancellationRequested();
    }

    public async ValueTask DisposeAsync()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _stop.Cancel();
        }

        await DrainAsync();
        _stop.Dispose();
    }
}
