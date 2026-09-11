using ManyMeterSimulator.Brain;

namespace ManyMeterSimulator.Testing;

public sealed record MqttStressState(string Phase = "Idle", string? Detail = null,
    long PreparedMeters = 0, long PreparedMessages = 0, long PreparedBytes = 0,
    DateTimeOffset? PreparedAtUtc = null, TimeSpan PreparationTime = default, MqttPushSummary? Result = null)
{
    public MqttPushRequest? Request { get; init; }
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

    public void Start(MqttPushRequest request, bool prepare)
    {
        request = request with { BatchIds = request.BatchIds.ToArray() };
        request.Validate();
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_state.IsActive || _stopping || !_operation.IsCompleted)
                throw new InvalidOperationException("Stop or finish the current MQTT stress run first.");
            _cts?.Dispose();
            _cts = CancellationTokenSource.CreateLinkedTokenSource(lifetime.ApplicationStopping);
            _state = new MqttStressState("Connecting", "Opening publish-only connections; no payloads sent yet.") { Request = request };
            _operation = Task.Run(() => StartAsync(request, prepare, _cts.Token));
        }
        Changed?.Invoke();
    }

    private async Task StartAsync(MqttPushRequest request, bool prepare, CancellationToken ct)
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
                SetState(new MqttStressState("Sending", "Generating and publishing. Watch incoming message rate in EMQX."));
                var result = await run.SendLiveAsync();
                SetState(new MqttStressState("Completed", Result: result));
            }
        }
        catch (OperationCanceledException) { SetState(new MqttStressState("Stopped", run?.InvalidReason ?? "Run stopped. In-flight delivery may be unconfirmed.")); }
        catch (Exception ex) { SetState(new MqttStressState("Failed", ex.Message)); }
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
                _state = new MqttStressState("Stopped", "Prepared data and publishing connections released.");
            }
            Changed?.Invoke();
        }
    }

    private void SetState(MqttStressState state)
    {
        lock (_sync) if (!_stopping) _state = state with { Request = state.Request ?? _state.Request };
        Changed?.Invoke();
    }

    public async ValueTask DisposeAsync()
    {
        lock (_sync) { if (_disposed) return; _disposed = true; }
        await StopAsync();
        _cts?.Dispose();
    }
}
