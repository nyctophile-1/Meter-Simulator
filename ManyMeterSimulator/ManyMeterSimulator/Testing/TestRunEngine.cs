using System.Diagnostics;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Testing;

/// <summary>
/// Runs one test plan at a time. Schedules a push loop for <see cref="TestPlan.CollectionDurationMin"/>,
/// fires every <see cref="TestPlan.PushIntervalSec"/>, collects per-tick results, writes the report
/// to disk, then raises <see cref="RunCompleted"/> so the UI can trigger an auto-download.
/// </summary>
public sealed class TestRunEngine : IAsyncDisposable
{
    private readonly MeterRegistry _meters;
    private readonly NetworkRegistry _network;
    private readonly PushCoordinator _push;
    private readonly TestRunStore _store;
    private readonly ILogger<TestRunEngine> _logger;

    private CancellationTokenSource? _cts;
    private Task? _runTask;
    private TestRunState? _active;
    private readonly object _lock = new();

    public TestRunEngine(
        MeterRegistry meters,
        NetworkRegistry network,
        PushCoordinator push,
        TestRunStore store,
        ILogger<TestRunEngine> logger)
    {
        _meters = meters;
        _network = network;
        _push = push;
        _store = store;
        _logger = logger;
    }

    /// <summary>Fires whenever the run status or a tick lands — for the Testing page to re-render.</summary>
    public event Action? Changed;

    /// <summary>Fires once on successful completion with the persisted report path.</summary>
    public event Action<TestRunReport>? RunCompleted;

    public TestRunState? ActiveRun
    {
        get { lock (_lock) return _active; }
    }

    public bool IsActive
    {
        get { lock (_lock) return _active is not null && _active.Status is TestRunStatus.Scheduled or TestRunStatus.Running; }
    }

    /// <summary>
    /// Schedules a run. Throws if another run is already active.
    /// If <paramref name="startAt"/> is in the past or within 2s, starts immediately.
    /// </summary>
    public void ScheduleRun(TestPlan plan, IReadOnlyList<int> batchIds, DateTimeOffset startAt)
    {
        lock (_lock)
        {
            if (IsActive)
            {
                throw new InvalidOperationException("A test run is already active. Cancel it first.");
            }

            _cts = new CancellationTokenSource();
            int expectedTicks = (int)Math.Floor(plan.CollectionDurationMin * 60.0 / plan.PushIntervalSec);

            _active = new TestRunState
            {
                RunId = Guid.NewGuid().ToString("N")[..12],
                PlanId = plan.Id,
                PlanName = plan.DisplayName,
                Status = TestRunStatus.Scheduled,
                ScheduledStartUtc = startAt,
                ExpectedTicks = expectedTicks,
            };

            _runTask = Task.Run(() => RunAsync(plan, batchIds, startAt, _active, _cts.Token));
        }

        Changed?.Invoke();
    }

    public void Cancel()
    {
        CancellationTokenSource? cts;
        lock (_lock)
        {
            cts = _cts;
            if (_active is { } s && s.Status is TestRunStatus.Scheduled or TestRunStatus.Running)
            {
                s.Status = TestRunStatus.Cancelled;
            }
        }

        cts?.Cancel();
        Changed?.Invoke();
    }

    // ── Run loop ─────────────────────────────────────────────────────────────────────────────────

    private async Task RunAsync(
        TestPlan plan,
        IReadOnlyList<int> batchIds,
        DateTimeOffset startAt,
        TestRunState state,
        CancellationToken ct)
    {
        // ── Wait for scheduled start ──
        TimeSpan waitFor = startAt - DateTimeOffset.UtcNow;
        if (waitFor > TimeSpan.FromSeconds(2))
        {
            try { await Task.Delay(waitFor, ct); }
            catch (OperationCanceledException) { Finalize(state, Array.Empty<TickRecord>(), plan); return; }
        }

        lock (_lock)
        {
            state.Status = TestRunStatus.Running;
            state.ActualStartUtc = DateTimeOffset.UtcNow;
        }

        Changed?.Invoke();

        var interval = TimeSpan.FromSeconds(plan.PushIntervalSec);
        var runEnd = DateTimeOffset.UtcNow.AddMinutes(plan.CollectionDurationMin);
        var ticks = new List<TickRecord>();
        int tickNumber = 0;

        while (!ct.IsCancellationRequested && DateTimeOffset.UtcNow < runEnd)
        {
            tickNumber++;
            DateTimeOffset tickStart = DateTimeOffset.UtcNow;

            TickRecord tick = await RunTickAsync(tickNumber, tickStart, batchIds, ct);
            ticks.Add(tick);

            lock (_lock)
            {
                state.CompletedTicks = tickNumber;
                state.LastTickSummary = $"Tick {tickNumber}: {tick.TotalSent} sent, {tick.TotalFailed} failed";
                state.NextTickUtc = tickStart + interval < runEnd ? tickStart + interval : null;
            }

            Changed?.Invoke();

            // Wait for next tick unless we're past the run end
            DateTimeOffset nextTick = tickStart + interval;
            if (nextTick < runEnd && !ct.IsCancellationRequested)
            {
                TimeSpan wait = nextTick - DateTimeOffset.UtcNow;
                if (wait > TimeSpan.Zero)
                {
                    try { await Task.Delay(wait, ct); }
                    catch (OperationCanceledException) { break; }
                }
            }
        }

        Finalize(state, ticks, plan);
    }

    private async Task<TickRecord> RunTickAsync(
        int tickNumber,
        DateTimeOffset tickStart,
        IReadOnlyList<int> batchIds,
        CancellationToken ct)
    {
        var batchResults = new List<BatchTickResult>();

        foreach (int batchId in batchIds)
        {
            if (ct.IsCancellationRequested) break;

            var batch = _meters.Batches.FirstOrDefault(b => b.Id == batchId);
            if (batch is null) continue;

            var sw = Stopwatch.StartNew();
            BatchTickResult tickResult;
            try
            {
                PushBatchResult r = await _push.PushBatchAsync(batchId, destination: null, ct);
                sw.Stop();
                tickResult = new BatchTickResult
                {
                    BatchId = batchId,
                    BatchName = batch.Name,
                    EnvironmentKey = batch.EnvironmentKey,
                    Total = r.Total,
                    Sent = r.Sent,
                    Failed = r.Failed,
                    DurationMs = sw.ElapsedMilliseconds,
                    Error = r.Ok ? null : r.Error,
                };
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                sw.Stop();
                tickResult = new BatchTickResult
                {
                    BatchId = batchId,
                    BatchName = batch.Name,
                    EnvironmentKey = batch.EnvironmentKey,
                    Total = (int)batch.Count,
                    Sent = 0,
                    Failed = (int)batch.Count,
                    DurationMs = sw.ElapsedMilliseconds,
                    Error = ex.Message,
                };
            }

            batchResults.Add(tickResult);
        }

        return new TickRecord
        {
            TickNumber = tickNumber,
            TimestampUtc = tickStart,
            TotalSent = batchResults.Sum(r => r.Sent),
            TotalFailed = batchResults.Sum(r => r.Failed),
            Batches = batchResults,
        };
    }

    private void Finalize(TestRunState state, IReadOnlyList<TickRecord> ticks, TestPlan plan)
    {
        DateTimeOffset endUtc = DateTimeOffset.UtcNow;
        DateTimeOffset startUtc;
        TestRunStatus finalStatus;

        lock (_lock)
        {
            startUtc = state.ActualStartUtc ?? state.ScheduledStartUtc;
            finalStatus = state.Status is TestRunStatus.Cancelled or TestRunStatus.Failed
                ? state.Status
                : TestRunStatus.Completed;
            state.Status = finalStatus;
            state.NextTickUtc = null;
            _cts?.Dispose();
            _cts = null;
        }

        TestRunReport report = BuildReport(state, ticks, plan, startUtc, endUtc, finalStatus);

        try
        {
            _store.Save(report);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save report for run {RunId}", state.RunId);
        }

        Changed?.Invoke();

        if (finalStatus == TestRunStatus.Completed)
        {
            RunCompleted?.Invoke(report);
        }
    }

    // ── Report builder ───────────────────────────────────────────────────────────────────────────

    private static TestRunReport BuildReport(
        TestRunState state,
        IReadOnlyList<TickRecord> ticks,
        TestPlan plan,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TestRunStatus status)
    {
        double elapsedMin = Math.Max(1, (endUtc - startUtc).TotalMinutes);

        // All batch-tick durations for percentile calculations
        var allDurations = ticks
            .SelectMany(t => t.Batches)
            .Select(b => (double)b.DurationMs)
            .OrderBy(d => d)
            .ToList();

        int totalSent = ticks.Sum(t => t.TotalSent);
        int totalFailed = ticks.Sum(t => t.TotalFailed);
        int totalExpected = totalSent + totalFailed;
        double successPct = totalExpected == 0 ? 0 : totalSent * 100.0 / totalExpected;
        double throughput = totalSent / elapsedMin;
        double medianMs = Percentile(allDurations, 50);
        double p95Ms = Percentile(allDurations, 95);
        int score = ComputeScore(throughput, successPct, p95Ms);

        // Per-environment breakdown
        var envKeys = state.Status == TestRunStatus.Completed
            ? ticks.SelectMany(t => t.Batches)
                   .Select(b => b.EnvironmentKey ?? "")
                   .Distinct(StringComparer.OrdinalIgnoreCase)
                   .ToList()
            : plan.EnvironmentKeys;

        var envReports = envKeys.Select(envKey =>
        {
            var envBatches = ticks
                .SelectMany(t => t.Batches)
                .Where(b => string.Equals(b.EnvironmentKey ?? "", envKey, StringComparison.OrdinalIgnoreCase))
                .ToList();

            var envDurations = envBatches.Select(b => (double)b.DurationMs).OrderBy(d => d).ToList();
            int eSent = envBatches.Sum(b => b.Sent);
            int eFailed = envBatches.Sum(b => b.Failed);
            int eExpected = eSent + eFailed;
            double ePct = eExpected == 0 ? 0 : eSent * 100.0 / eExpected;
            double eThrough = eSent / elapsedMin;
            double eMedian = Percentile(envDurations, 50);
            double eP95 = Percentile(envDurations, 95);

            // Per-batch summaries within this env
            var batchIds = envBatches.Select(b => b.BatchId).Distinct().ToList();
            var batchReports = batchIds.Select(bid =>
            {
                var br = envBatches.Where(b => b.BatchId == bid).ToList();
                var bDur = br.Select(b => (double)b.DurationMs).OrderBy(d => d).ToList();
                return new BatchRunReport
                {
                    BatchId = bid,
                    BatchName = br.First().BatchName,
                    EnvironmentKey = envKey,
                    TotalMetersPushed = br.Sum(b => b.Sent),
                    TotalMetersExpected = br.Sum(b => b.Sent + b.Failed),
                    TotalMetersFailed = br.Sum(b => b.Failed),
                    SuccessRatePct = br.Sum(b => b.Sent + b.Failed) == 0 ? 0
                        : br.Sum(b => b.Sent) * 100.0 / br.Sum(b => b.Sent + b.Failed),
                    MedianPushDurationMs = Percentile(bDur, 50),
                    P95PushDurationMs = Percentile(bDur, 95),
                };
            }).ToList();

            return new EnvironmentRunReport
            {
                EnvironmentKey = envKey,
                TotalMetersPushed = eSent,
                TotalMetersExpected = eExpected,
                TotalMetersFailed = eFailed,
                SuccessRatePct = ePct,
                ThroughputPerMin = eThrough,
                MedianPushDurationMs = eMedian,
                P95PushDurationMs = eP95,
                BenchScore = ComputeScore(eThrough, ePct, eP95),
                Batches = batchReports,
            };
        }).ToList();

        return new TestRunReport
        {
            RunId = state.RunId,
            PlanId = state.PlanId,
            PlanName = state.PlanName,
            StartUtc = startUtc,
            EndUtc = endUtc,
            FinalStatus = status,
            PushIntervalSec = plan.PushIntervalSec,
            CollectionDurationMin = plan.CollectionDurationMin,
            EnvironmentKeys = envKeys,
            TotalTicks = ticks.Count,
            TotalMetersPushed = totalSent,
            TotalMetersExpected = totalExpected,
            TotalMetersFailed = totalFailed,
            SuccessRatePct = successPct,
            ThroughputPerMin = throughput,
            MedianPushDurationMs = medianMs,
            P95PushDurationMs = p95Ms,
            BenchScore = score,
            Environments = envReports,
            Ticks = ticks.ToList(),
        };
    }

    /// <summary>
    /// BenchScore = round( throughput_per_min / (1 + P95_sec) × success_rate_pct )
    /// Rewards: more meters pushed per minute, faster P95 tail, fewer failures.
    /// </summary>
    public static int ComputeScore(double throughputPerMin, double successRatePct, double p95Ms)
    {
        if (throughputPerMin <= 0) return 0;
        double p95Sec = p95Ms / 1000.0;
        return (int)Math.Round(throughputPerMin / (1 + p95Sec) * successRatePct);
    }

    private static double Percentile(IReadOnlyList<double> sorted, int pct)
    {
        if (sorted.Count == 0) return 0;
        if (sorted.Count == 1) return sorted[0];
        double rank = pct / 100.0 * (sorted.Count - 1);
        int lo = (int)rank;
        int hi = Math.Min(lo + 1, sorted.Count - 1);
        return sorted[lo] + (rank - lo) * (sorted[hi] - sorted[lo]);
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        if (_runTask is not null)
        {
            try { await _runTask; }
            catch (OperationCanceledException) { }
        }
    }
}
