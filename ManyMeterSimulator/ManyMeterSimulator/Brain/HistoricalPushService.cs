namespace ManyMeterSimulator.Brain;

public sealed record HistoricalPushState(string Phase = "Idle", HistoricalPushRequest? Request = null,
    HistoricalPushProgress? Progress = null, string? Error = null)
{
    public bool IsActive => Phase is "Connecting" or "Sending" or "Stopping";
}

public sealed class HistoricalPushService(PushCoordinator push, IHostApplicationLifetime lifetime) : IAsyncDisposable
{
    private readonly object _sync = new();
    private CancellationTokenSource? _stop;
    private Task _work = Task.CompletedTask;
    private HistoricalPushState _state = new();
    private HistoricalPushRun? _run;
    private bool _disposed;
    public HistoricalPushState State { get { lock (_sync) return _state; } }

    public void Start(HistoricalPushRequest request)
    {
        request = request with { BatchIds = request.BatchIds.ToArray() };
        request.Validate();
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_work.IsCompleted) throw new InvalidOperationException("Stop or finish the current historical push first.");
            _stop?.Dispose();
            _stop = CancellationTokenSource.CreateLinkedTokenSource(lifetime.ApplicationStopping);
            _state = new("Connecting", request);
            var token = _stop.Token;
            _work = Task.Run(() => RunAsync(request, token));
        }
    }

    private async Task RunAsync(HistoricalPushRequest request, CancellationToken token)
    {
        string phase = "Completed";
        string? error = null;
        try
        {
            await using var run = await push.OpenHistoricalRunAsync(request, token);
            lock (_sync)
            {
                run.SetRecordsPerSecond(_state.Request!.RecordsPerSecond);
                _run = run;
            }
            await run.SendAsync(progress =>
            {
                lock (_sync) _state = _state with { Phase = token.IsCancellationRequested ? "Stopping" : "Sending", Progress = progress };
            }, token);
            if (State.Progress?.Failed > 0) phase = "Completed with failures";
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { phase = "Stopped"; }
        catch (Exception ex) { phase = "Failed"; error = ex.Message; }
        finally
        {
            lock (_sync)
            {
                _run = null;
                _state = _state with { Phase = phase, Error = error };
            }
        }
    }

    public void SetRecordsPerSecond(int rate)
    {
        if (rate != 0) Networking.Mqtt.MqttPublishRateLimiter.Validate(rate);
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_state.Phase is not ("Connecting" or "Sending") || _state.Request is null)
                throw new InvalidOperationException("There is no active historical push to adjust.");
            _run?.SetRecordsPerSecond(rate);
            _state = _state with { Request = _state.Request with { RecordsPerSecond = rate } };
        }
    }

    public async Task StopAsync()
    {
        Task work;
        lock (_sync)
        {
            work = _work;
            if (!work.IsCompleted)
            {
                _state = _state with { Phase = "Stopping" };
                _stop?.Cancel();
            }
        }
        await work;
    }

    public async ValueTask DisposeAsync()
    {
        lock (_sync) _disposed = true;
        await StopAsync();
        lock (_sync) { _stop?.Dispose(); _stop = null; }
    }
}
