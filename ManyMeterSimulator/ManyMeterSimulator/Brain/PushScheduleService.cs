using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Brain;

/// <summary>
/// Runs on-demand push on a timer for an operator-picked set of batches — the "loop push" the
/// Testing page's Configure Loop button drives.
///
/// <para>
/// Deliberately one schedule at a time, in memory, not persisted: this is a testing aid for proving
/// a path stays up under repeated push, not a durable job system. Starting a new schedule replaces
/// whatever was running. Nothing here survives a restart, and nothing should — someone must be
/// looking at the Testing page to have configured it, and it would be surprising to find a loop
/// still firing from a schedule set up in a different session, possibly against a batch that no
/// longer makes sense to push.
/// </para>
/// </summary>
public sealed class PushScheduleService : IAsyncDisposable
{
    /// <summary>The only intervals offered — matches the Testing page's picker exactly.</summary>
    public static readonly IReadOnlyList<int> AllowedIntervalMinutes = new[] { 1, 5, 10, 15, 30, 60 };

    private readonly MeterRegistry _registry;
    private readonly PushCoordinator _push;
    private readonly ILogger<PushScheduleService> _logger;
    private readonly object _lock = new();

    private CancellationTokenSource? _cts;
    private Task? _loopTask;
    private PushScheduleState _state = PushScheduleState.Idle;

    public PushScheduleService(MeterRegistry registry, PushCoordinator push, ILogger<PushScheduleService> logger)
    {
        _registry = registry;
        _push = push;
        _logger = logger;
    }

    /// <summary>Raised whenever <see cref="State"/> changes — a run started, a tick landed, it stopped.</summary>
    public event Action? Changed;

    public PushScheduleState State
    {
        get
        {
            lock (_lock)
            {
                return _state;
            }
        }
    }

    /// <summary>
    /// Starts looping push over <paramref name="batchIds"/> every <paramref name="intervalMinutes"/>.
    /// Replaces any schedule already running. Fires once immediately, then on the interval — the
    /// point of this button is "prove it stays up", and waiting a full interval for the first data
    /// point would make that check slower for no reason.
    /// </summary>
    public void Start(IReadOnlyList<int> batchIds, int intervalMinutes)
    {
        if (batchIds.Count == 0)
        {
            throw new ArgumentException("Pick at least one batch.", nameof(batchIds));
        }

        if (!AllowedIntervalMinutes.Contains(intervalMinutes))
        {
            throw new ArgumentException(
                $"Interval must be one of {string.Join(", ", AllowedIntervalMinutes)} minutes.", nameof(intervalMinutes));
        }

        StopInternal();

        var cts = new CancellationTokenSource();
        lock (_lock)
        {
            _cts = cts;
            _state = new PushScheduleState(
                IsRunning: true,
                BatchIds: batchIds.ToArray(),
                IntervalMinutes: intervalMinutes,
                LastRunUtc: null,
                NextRunUtc: DateTimeOffset.UtcNow,
                LastSummary: null);
            _loopTask = Task.Run(() => RunLoopAsync(batchIds.ToArray(), intervalMinutes, cts.Token));
        }

        Changed?.Invoke();
    }

    /// <summary>Stops the loop. A no-op if nothing is running.</summary>
    public void Stop()
    {
        bool wasRunning = StopInternal();
        if (wasRunning)
        {
            Changed?.Invoke();
        }
    }

    private bool StopInternal()
    {
        CancellationTokenSource? cts;
        lock (_lock)
        {
            if (_cts is null)
            {
                return false;
            }

            cts = _cts;
            _cts = null;
            _state = _state with { IsRunning = false, NextRunUtc = null };
        }

        cts.Cancel();
        cts.Dispose();
        return true;
    }

    private async Task RunLoopAsync(IReadOnlyList<int> batchIds, int intervalMinutes, CancellationToken cancellationToken)
    {
        var period = TimeSpan.FromMinutes(intervalMinutes);

        while (!cancellationToken.IsCancellationRequested)
        {
            await RunOnceAsync(batchIds, cancellationToken);

            lock (_lock)
            {
                if (_state.IsRunning)
                {
                    _state = _state with { NextRunUtc = DateTimeOffset.UtcNow + period };
                }
            }

            Changed?.Invoke();

            try
            {
                await Task.Delay(period, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task RunOnceAsync(IReadOnlyList<int> batchIds, CancellationToken cancellationToken)
    {
        var results = new List<string>();

        foreach (int batchId in batchIds)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            MeterBatch? batch = _registry.Batches.FirstOrDefault(b => b.Id == batchId);
            if (batch is null)
            {
                // Deleted mid-schedule. Named in the summary rather than silently skipped, so an
                // operator watching the Testing page can see why a batch stopped reporting.
                results.Add($"batch {batchId}: deleted");
                continue;
            }

            try
            {
                PushBatchResult result = await _push.PushBatchAsync(batchId, destination: null, cancellationToken);
                results.Add(result.Ok
                    ? $"{batch.Name}: {result.Sent}/{result.Total}"
                    : $"{batch.Name}: {result.Error}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Loop push failed for batch {Batch}", batch.Name);
                results.Add($"{batch.Name}: {ex.Message}");
            }
        }

        string summary = string.Join("; ", results);
        _logger.LogInformation("Loop push tick: {Summary}", summary);

        lock (_lock)
        {
            _state = _state with { LastRunUtc = DateTimeOffset.UtcNow, LastSummary = summary };
        }
    }

    public async ValueTask DisposeAsync()
    {
        StopInternal();
        if (_loopTask is not null)
        {
            try
            {
                await _loopTask;
            }
            catch (OperationCanceledException)
            {
            }
        }
    }
}

/// <summary>Point-in-time snapshot of the loop push schedule, for the Testing page to render.</summary>
public sealed record PushScheduleState(
    bool IsRunning,
    IReadOnlyList<int> BatchIds,
    int IntervalMinutes,
    DateTimeOffset? LastRunUtc,
    DateTimeOffset? NextRunUtc,
    string? LastSummary)
{
    public static readonly PushScheduleState Idle = new(false, Array.Empty<int>(), 0, null, null, null);
}
