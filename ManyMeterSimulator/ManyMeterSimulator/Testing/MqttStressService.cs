using ManyMeterSimulator.Brain;

namespace ManyMeterSimulator.Testing;

public sealed record MqttStressState(string Phase = "Idle", string? Detail = null,
    long PreparedMeters = 0, long PreparedMessages = 0, long PreparedBytes = 0,
    DateTimeOffset? PreparedAtUtc = null, TimeSpan PreparationTime = default, MqttPushSummary? Result = null)
{
    public MqttPushRequest? Request { get; init; }
    public MqttLoopOptions? Loop { get; init; }
    public long? CompletedCycles { get; init; }
    public bool IsActive => Phase is "Connecting" or "Preparing" or "Ready" or "Sending" or "Stopping";
    public bool IsBusy => IsActive && Phase != "Ready";
}

/// <summary>One local stress run, shared across Testing-page sessions. EMQX owns rate monitoring.</summary>
public sealed class MqttStressService(PushCoordinator push, IHostApplicationLifetime lifetime) : IAsyncDisposable
{
    private readonly object _sync = new();
    private CancellationTokenSource? _cts;
    private Task _operation = Task.CompletedTask;
    private MqttPushRun? _run;
    private MqttStressState _state = new();
    private bool _stopping;
    private bool _disposed;
    public event Action? Changed;
    public MqttStressState State { get { lock (_sync) return _state; } }

    public void Start(MqttPushRequest request, bool prepare, MqttLoopOptions? loop = null)
    {
        request = request with { BatchIds = request.BatchIds.ToArray() };
        request.Validate();
        loop?.Validate();
        if (prepare && loop is not null) throw new ArgumentException("Continuous loops generate fresh payloads; prepared data is single-use.");
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_state.IsActive || _stopping || !_operation.IsCompleted)
                throw new InvalidOperationException("Stop or finish the current MQTT stress run first.");
            _cts?.Dispose();
            _cts = CancellationTokenSource.CreateLinkedTokenSource(lifetime.ApplicationStopping);
            _state = new MqttStressState("Connecting", "Opening publish-only connections; no payloads sent yet.") { Request = request, Loop = loop };
            _operation = Task.Run(() => StartAsync(request, prepare, loop, _cts.Token));
        }
        Changed?.Invoke();
    }

    private async Task StartAsync(MqttPushRequest request, bool prepare, MqttLoopOptions? loop, CancellationToken ct)
    {
        MqttPushRun? run = null;
        bool keep = false;
        try
        {
            run = await push.OpenMqttRunAsync(request, ct);
            lock (_sync) _run = run;
            ct.ThrowIfCancellationRequested();
            if (prepare)
            {
                SetState(new MqttStressState("Preparing", "Building payloads in memory; no payloads sent yet."));
                await run.PrepareAsync();
                ct.ThrowIfCancellationRequested();
                keep = true;
                SetState(new MqttStressState("Ready", "Connections are ready. Fire once within five minutes, or discard.",
                    run.PreparedMeters, run.PreparedMessages, run.PreparedBytes, run.PreparedAtUtc, run.PreparationTime));
            }
            else
            {
                SetState(new MqttStressState("Sending", loop is null
                    ? "Generating and publishing one fleet pass. Watch incoming message rate in EMQX."
                    : $"Looping with fresh payloads {(loop.DurationMinutes == 0 ? "until stopped" : $"for {loop.DurationMinutes} minutes")}. Watch incoming message rate in EMQX."));
                if (loop is null)
                    SetState(new MqttStressState("Completed", Result: await run.SendLiveAsync()));
                else
                {
                    var result = await run.SendLoopAsync(loop);
                    SetState(new MqttStressState("Completed", Result: result.Totals) { CompletedCycles = result.CompletedCycles });
                }
            }
        }
        catch (OperationCanceledException) { SetState(new MqttStressState(run?.InvalidReason is null ? "Stopped" : "Failed", run?.InvalidReason ?? "Run stopped. In-flight delivery may be unconfirmed.", Result: run?.LoopResult?.Totals) { CompletedCycles = run?.LoopResult?.CompletedCycles }); }
        catch (Exception ex) { SetState(new MqttStressState("Failed", ex.Message, Result: run?.LoopResult?.Totals) { CompletedCycles = run?.LoopResult?.CompletedCycles }); }
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
            _state = _state with { Phase = "Sending", Detail = "Publishing the prepared dataset. Watch incoming message rate in EMQX." };
            _operation = Task.Run(() => FireAsync(run));
        }
        Changed?.Invoke();
    }

    private async Task FireAsync(MqttPushRun run)
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
            _state = _state with { Phase = "Stopping", Detail = "Stopping and releasing publishers and prepared data." };
            operation = _operation;
        }
        Changed?.Invoke();
        try
        {
            await operation;
            MqttPushRun? run;
            lock (_sync) { run = _run; _run = null; }
            if (run is not null) await run.DisposeAsync();
        }
        finally
        {
            lock (_sync)
            {
                _stopping = false;
                _state = _state with { Phase = "Stopped", Detail = "Publishing connections released. In-flight delivery may be unconfirmed.",
                    PreparedMeters = 0, PreparedMessages = 0, PreparedBytes = 0, PreparedAtUtc = null };
            }
            Changed?.Invoke();
        }
    }

    private void SetState(MqttStressState state)
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
