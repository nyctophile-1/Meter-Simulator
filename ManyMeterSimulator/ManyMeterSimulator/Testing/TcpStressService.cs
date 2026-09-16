using ManyMeterSimulator.Brain;

namespace ManyMeterSimulator.Testing;

public sealed record TcpStressState(string Phase = "Idle", string? Detail = null,
    long PreparedMeters = 0, long PreparedMessages = 0, long PreparedBytes = 0,
    DateTimeOffset? PreparedAtUtc = null, TimeSpan PreparationTime = default, TcpPushSummary? Result = null)
{
    public TcpPushRequest? Request { get; init; }
    public TcpLoopOptions? Loop { get; init; }
    public long? CompletedCycles { get; init; }
    public bool IsActive => Phase is "Connecting" or "Preparing" or "Ready" or "Sending" or "Stopping";
    public bool IsBusy => IsActive && Phase != "Ready";
}

/// <summary>One local stress run, shared across Testing-page sessions. Each meter retains its source address.</summary>
public sealed class TcpStressService(PushCoordinator push, IHostApplicationLifetime lifetime) : IAsyncDisposable
{
    private readonly object _sync = new();
    private CancellationTokenSource? _cts;
    private Task _operation = Task.CompletedTask;
    private TcpPushRun? _run;
    private TcpStressState _state = new();
    private bool _stopping;
    private bool _disposed;
    public event Action? Changed;
    public TcpStressState State { get { lock (_sync) return _state; } }

    public void Start(TcpPushRequest request, bool prepare, TcpLoopOptions? loop = null)
    {
        request = request with { BatchIds = request.BatchIds.ToArray() };
        request.Validate();
        loop?.Validate();
        if (prepare && loop is not null) throw new ArgumentException("Continuous loops generate fresh payloads; prepared data is single-use.");
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_state.IsActive || _stopping || !_operation.IsCompleted)
                throw new InvalidOperationException("Stop or finish the current TCP stress run first.");
            _cts?.Dispose();
            _cts = CancellationTokenSource.CreateLinkedTokenSource(lifetime.ApplicationStopping);
            _state = new TcpStressState("Connecting", "Checking selected TCP batches and targets; no payloads sent yet.") { Request = request, Loop = loop };
            _operation = Task.Run(() => StartAsync(request, prepare, loop, _cts.Token));
        }
        Changed?.Invoke();
    }

    private async Task StartAsync(TcpPushRequest request, bool prepare, TcpLoopOptions? loop, CancellationToken ct)
    {
        TcpPushRun? run = null;
        bool keep = false;
        try
        {
            run = await push.OpenTcpRunAsync(request, ct);
            lock (_sync) _run = run;
            ct.ThrowIfCancellationRequested();
            if (prepare)
            {
                SetState(new TcpStressState("Preparing", "Building payloads in memory; no payloads sent yet."));
                await run.PrepareAsync();
                ct.ThrowIfCancellationRequested();
                keep = true;
                SetState(new TcpStressState("Ready", "Payloads are ready. Fire once within five minutes to connect and send, or discard.",
                    run.PreparedMeters, run.PreparedMessages, run.PreparedBytes, run.PreparedAtUtc, run.PreparationTime));
            }
            else
            {
                SetState(new TcpStressState("Sending", loop is null
                    ? "Generating and publishing one fleet pass. Measure received traffic at the TCP listener."
                    : $"Looping with fresh payloads {(loop.DurationMinutes == 0 ? "until stopped" : $"for {loop.DurationMinutes} minutes")}. Measure received traffic at the TCP listener."));
                if (loop is null)
                    SetState(new TcpStressState("Completed", Result: await run.SendLiveAsync()));
                else
                {
                    var result = await run.SendLoopAsync(loop);
                    SetState(new TcpStressState("Completed", Result: result.Totals) { CompletedCycles = result.CompletedCycles });
                }
            }
        }
        catch (OperationCanceledException) { SetState(new TcpStressState(run?.InvalidReason is null ? "Stopped" : "Failed", run?.InvalidReason ?? "Run stopped. In-flight delivery may be unconfirmed.", Result: run?.LoopResult?.Totals ?? run?.LastPass) { CompletedCycles = run?.LoopResult?.CompletedCycles }); }
        catch (Exception ex) { SetState(new TcpStressState("Failed", ex.Message, Result: run?.LoopResult?.Totals ?? run?.LastPass) { CompletedCycles = run?.LoopResult?.CompletedCycles }); }
        finally
        {
            if (!keep && run is not null)
            {
                await run.DisposeAsync();
                lock (_sync) if (ReferenceEquals(_run, run)) _run = null;
            }
        }
    }

    public void Fire()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_state.Phase != "Ready" || _run is null || _stopping)
                throw new InvalidOperationException("Wait for preparation to finish before firing.");
            var run = _run;
            _state = _state with { Phase = "Sending", Detail = "Publishing the prepared dataset. Measure received traffic at the TCP listener." };
            _operation = Task.Run(() => FireAsync(run));
        }
        Changed?.Invoke();
    }

    private async Task FireAsync(TcpPushRun run)
    {
        try
        {
            var result = await run.FireAsync();
            SetState(State with { Phase = "Completed", Detail = null, Result = result });
        }
        catch (OperationCanceledException) { SetState(State with { Phase = "Stopped", Detail = run.InvalidReason ?? "Run stopped. In-flight delivery may be unconfirmed." }); }
        catch (Exception ex) { SetState(State with { Phase = "Failed", Detail = ex.Message }); }
        finally
        {
            await run.DisposeAsync();
            lock (_sync) if (ReferenceEquals(_run, run)) _run = null;
        }
    }

    public async Task StopAsync()
    {
        Task operation;
        lock (_sync)
        {
            if (_stopping) return;
            _stopping = true;
            _cts?.Cancel();
            _state = _state with { Phase = "Stopping", Detail = "Stopping and releasing sockets and prepared data." };
            operation = _operation;
        }
        Changed?.Invoke();
        try
        {
            await operation;
            TcpPushRun? run;
            lock (_sync) { run = _run; _run = null; }
            if (run is not null) await run.DisposeAsync();
        }
        finally
        {
            lock (_sync)
            {
                _stopping = false;
                _state = _state with { Phase = "Stopped", Detail = "TCP sockets and prepared data released. In-flight delivery may be unconfirmed.",
                    PreparedMeters = 0, PreparedMessages = 0, PreparedBytes = 0, PreparedAtUtc = null };
            }
            Changed?.Invoke();
        }
    }

    private void SetState(TcpStressState state)
    {
        lock (_sync) _state = state with { Phase = _stopping ? "Stopping" : state.Phase,
            Request = state.Request ?? _state.Request, Loop = state.Loop ?? _state.Loop };
        Changed?.Invoke();
    }

    public async ValueTask DisposeAsync()
    {
        lock (_sync) { if (_disposed) return; _disposed = true; }
        await StopAsync();
        _cts?.Dispose();
    }
}
