using System.Diagnostics;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Testing;

/// <summary>
/// Runs one test plan at a time. Tasks within the plan execute concurrently, each after their
/// offset delay. System metrics (CPU, RAM) are sampled during the run and feed into the score.
/// </summary>
public sealed class TestRunEngine : IAsyncDisposable
{
    private readonly MeterRegistry _meters;
    private readonly NetworkRegistry _network;
    private readonly PushCoordinator _push;
    private readonly MeterSessionManager _sessions;
    private readonly SimulatorMetrics _simMetrics;
    private readonly TestRunStore _store;
    private readonly BadCommSettings _badComm;
    private readonly NetworkDelaySettings _networkDelay;
    private readonly ILogger<TestRunEngine> _logger;

    private CancellationTokenSource? _cts;
    private Task? _runTask;
    private TestRunState? _active;
    private readonly object _lock = new();

    public TestRunEngine(
        MeterRegistry meters,
        NetworkRegistry network,
        PushCoordinator push,
        MeterSessionManager sessions,
        SimulatorMetrics simMetrics,
        TestRunStore store,
        BadCommSettings badComm,
        NetworkDelaySettings networkDelay,
        ILogger<TestRunEngine> logger)
    {
        _meters = meters;
        _network = network;
        _push = push;
        _sessions = sessions;
        _simMetrics = simMetrics;
        _store = store;
        _badComm = badComm;
        _networkDelay = networkDelay;
        _logger = logger;
    }

    public event Action? Changed;
    public event Action<TestRunReport>? RunCompleted;

    public TestRunState? ActiveRun
    {
        get { lock (_lock) return _active; }
    }

    public bool IsActive
    {
        get { lock (_lock) return _active is { Status: TestRunStatus.Scheduled or TestRunStatus.Running }; }
    }

    public void ScheduleRun(TestPlan plan, string runLabel, DateTimeOffset startAt)
    {
        string? configurationError = GetBaseConfigurationError(plan);
        if (configurationError is not null)
            throw new InvalidOperationException(configurationError);

        lock (_lock)
        {
            if (IsActive) throw new InvalidOperationException("A test run is already active. Stop it first.");

            _cts = new CancellationTokenSource();
            _active = new TestRunState
            {
                RunId = Guid.NewGuid().ToString("N")[..12],
                PlanId = plan.Id,
                PlanName = plan.DisplayName,
                RunLabel = runLabel,
                Status = TestRunStatus.Scheduled,
                ScheduledStartUtc = startAt,
                TotalDurationMinutes = plan.TotalDurationMinutes,
            };

            _runTask = Task.Run(() => RunAsync(plan, runLabel, startAt, _active, _cts.Token));
        }

        Changed?.Invoke();
    }

    private string? GetBaseConfigurationError(TestPlan plan)
    {
        if (!plan.IsBasePlan)
            return null;

        if (plan.Id == TestPlanRegistry.PullPlanId)
        {
            PullListenerTask? pull = plan.Tasks.OfType<PullListenerTask>().FirstOrDefault();
            return pull is null || pull.DurationMinutes < 1
                ? "Test Pull needs a pull listener duration."
                : null;
        }

        if (plan.Id == TestPlanRegistry.PushPlanId)
        {
            BurstPushTask? push = plan.Tasks.OfType<BurstPushTask>().FirstOrDefault();
            if (push is null || string.IsNullOrWhiteSpace(push.EnvironmentKey))
                return "Test Push needs an environment selected in its push task.";
            if (push is null || push.BatchIds.Count == 0)
                return "Test Push needs at least one batch selected.";
            bool hasInvalidBatch = push.BatchIds.Any(id => _meters.Batches.FirstOrDefault(b => b.Id == id)?.Count < 100_000);
            if (hasInvalidBatch) return "Test Push batches must each contain at least 100,000 meters.";
            bool wrongEnvironment = push.BatchIds.Any(id => !string.Equals(_meters.Batches.FirstOrDefault(b => b.Id == id)?.EnvironmentKey, push.EnvironmentKey, StringComparison.OrdinalIgnoreCase));
            return wrongEnvironment ? "Every Test Push batch must belong to the selected environment." : null;
        }

        return null;
    }

    /// <summary>
    /// Stops an in-progress run and saves a report from every measurement completed up to this
    /// point. It does not change the benchmark sampling interval or scoring rules.
    /// </summary>
    public void StopNow()
    {
        CancellationTokenSource? cts;
        lock (_lock)
        {
            cts = _cts;
            if (_active is { Status: TestRunStatus.Scheduled or TestRunStatus.Running } s)
            {
                s.Status = TestRunStatus.Stopped;
                s.EndUtc = DateTimeOffset.UtcNow;
                s.LastSummary = "Stopped early; saving measurements collected so far.";
            }
        }

        cts?.Cancel();
        Changed?.Invoke();
    }

    // Kept for callers compiled against the earlier API. UI actions use StopNow.
    public void Cancel() => StopNow();

    // ── Run loop ────────────────────────────────────────────────────────────────────────────────

    private async Task RunAsync(TestPlan plan, string runLabel, DateTimeOffset startAt, TestRunState state, CancellationToken ct)
    {
        // Wait for scheduled start
        TimeSpan waitFor = startAt - DateTimeOffset.UtcNow;
        if (waitFor > TimeSpan.FromSeconds(2))
        {
            try { await Task.Delay(waitFor, ct); }
            catch (OperationCanceledException) { Finalize(state, Array.Empty<TaskRunResult>(), plan, runLabel, 0, 0, startAt, _simMetrics.Snapshot(_simMetrics.ActiveInboundExchanges)); return; }
        }

        DateTimeOffset actualStart = DateTimeOffset.UtcNow;
        lock (_lock)
        {
            state.Status = TestRunStatus.Running;
            state.ActualStartUtc = actualStart;
        }
        Changed?.Invoke();

        // Snapshot HES-side counters so we can compute the run-wide delta at finalize —
        // this is what tells us "how much did HES actually touch us during this run".
        OfficialBenchmarkProfile? profile = plan.IsOfficial ? ApplyOfficialProfile() : null;
        SimulatorMetricsSnapshot inboundBaseline = _simMetrics.Snapshot(_simMetrics.ActiveInboundExchanges);

        // Launch CPU sampler + all tasks concurrently
        using var cpuSampler = new CpuSampler();
        // A cancellation can interrupt a push mid-batch. Preserve the other task results and
        // finalize the partial report instead of allowing Task.WhenAll to abandon it.
        var taskTasks = plan.Tasks.Select(task => RunTaskSafelyAsync(task, actualStart, state, ct)).ToList();
        TaskRunResult[] taskResults = await Task.WhenAll(taskTasks);

        double avgCpu = cpuSampler.AveragePct;
        double peakRam = GetPeakRamMb();

        Finalize(state, taskResults, plan, runLabel, avgCpu, peakRam, actualStart, inboundBaseline, profile is not null);
        profile?.Restore(_badComm, _networkDelay);
    }

    private async Task<TaskRunResult> RunTaskSafelyAsync(TestTask task, DateTimeOffset runStart, TestRunState state, CancellationToken ct)
    {
        try { return await RunTaskAsync(task, runStart, state, ct); }
        catch (OperationCanceledException) { return new TaskRunResult(task); }
    }

    private async Task<TaskRunResult> RunTaskAsync(TestTask task, DateTimeOffset runStart, TestRunState state, CancellationToken ct)
    {
        // Respect offset
        if (task.OffsetMinutes > 0)
        {
            DateTimeOffset scheduledTaskStart = runStart.AddMinutes(task.OffsetMinutes);
            TimeSpan wait = scheduledTaskStart - DateTimeOffset.UtcNow;
            if (wait > TimeSpan.Zero)
            {
                try { await Task.Delay(wait, ct); }
                catch (OperationCanceledException) { return new TaskRunResult(task); }
            }
        }

        DateTimeOffset taskStart = DateTimeOffset.UtcNow;
        DateTimeOffset end = taskStart.AddMinutes(task.DurationMinutes);

        return task switch
        {
            PushLoopTask loop => await RunPushLoopAsync(loop, end, state, ct),
            PullListenerTask pull => await RunPullListenerAsync(pull, taskStart, end, state, ct),
            BurstPushTask burst => await RunBurstPushAsync(burst, end, state, ct),
            PartialPushTask partial => await RunPartialPushAsync(partial, end, state, ct),
            _ => new TaskRunResult(task),
        };
    }

    // ── Task runners ────────────────────────────────────────────────────────────────────────────

    private async Task<TaskRunResult> RunPushLoopAsync(PushLoopTask task, DateTimeOffset end, TestRunState state, CancellationToken ct)
    {
        var ticks = new List<TickRecord>();
        var interval = TimeSpan.FromSeconds(task.PushIntervalSec);
        int tickNum = 0;

        while (!ct.IsCancellationRequested && DateTimeOffset.UtcNow < end)
        {
            tickNum++;
            DateTimeOffset tickStart = DateTimeOffset.UtcNow;
            TickRecord tick = await RunPushTickAsync(tickNum, task.TaskId, tickStart, task.BatchIds, ct);
            ticks.Add(tick);

            lock (_lock)
                state.LastSummary = $"[{task.DisplayLabel}] tick {tickNum}: {tick.TotalSent} sent, {tick.TotalFailed} failed";
            Changed?.Invoke();

            DateTimeOffset nextTick = tickStart + interval;
            if (nextTick < end && !ct.IsCancellationRequested)
            {
                TimeSpan wait = nextTick - DateTimeOffset.UtcNow;
                if (wait > TimeSpan.Zero)
                {
                    try { await Task.Delay(wait, ct); }
                    catch (OperationCanceledException) { break; }
                }
            }
        }

        return new TaskRunResult(task, ticks);
    }

    private async Task<TaskRunResult> RunBurstPushAsync(BurstPushTask task, DateTimeOffset end, TestRunState state, CancellationToken ct)
    {
        var ticks = new List<TickRecord>();

        for (int burst = 1; burst <= task.BurstCount && !ct.IsCancellationRequested; burst++)
        {
            DateTimeOffset tickStart = DateTimeOffset.UtcNow;
            TickRecord tick = await RunPushTickAsync(burst, task.TaskId, tickStart, task.BatchIds, ct, task.MetersPerBatch);
            ticks.Add(tick);

            lock (_lock)
                state.LastSummary = $"[{task.DisplayLabel}] burst {burst}/{task.BurstCount}: {tick.TotalSent} sent";
            Changed?.Invoke();
        }

        return new TaskRunResult(task, ticks, task.BurstCount);
    }

    private async Task<TaskRunResult> RunPartialPushAsync(PartialPushTask task, DateTimeOffset end, TestRunState state, CancellationToken ct)
    {
        var ticks = new List<TickRecord>();
        IReadOnlyDictionary<int, int> limits = GetPartialBatchLimits(task);

        for (int burst = 1; burst <= task.BurstCount && !ct.IsCancellationRequested && DateTimeOffset.UtcNow < end; burst++)
        {
            TickRecord tick = await RunPushTickAsync(burst, task.TaskId, DateTimeOffset.UtcNow, task.BatchIds, ct, perBatchLimits: limits, selectRandomly: true);
            ticks.Add(tick);
            lock (_lock)
                state.LastSummary = $"[{task.DisplayLabel}] partial push {burst}/{task.BurstCount}: {tick.TotalSent} sent";
            Changed?.Invoke();
        }

        return new TaskRunResult(task, ticks, task.BurstCount);
    }

    private IReadOnlyDictionary<int, int> GetPartialBatchLimits(PartialPushTask task)
    {
        var batches = task.BatchIds
            .Select(id => _meters.Batches.FirstOrDefault(b => b.Id == id))
            .Where(b => b is not null)
            .Cast<MeterBatch>()
            .ToList();
        if (task.Mode == PartialPushMode.Percentage)
            return batches.ToDictionary(b => b.Id, b => Math.Min((int)b.Count, Math.Max(0, (int)Math.Ceiling(b.Count * Math.Clamp(task.Percentage, 0, 100) / 100.0))));

        int requested = Math.Max(0, task.MeterCount);
        long fleetSize = batches.Sum(b => b.Count);
        requested = (int)Math.Min(requested, fleetSize);
        var limits = batches.ToDictionary(b => b.Id, b => (int)Math.Floor(requested * (b.Count / (double)Math.Max(1, fleetSize))));
        int assigned = limits.Values.Sum();
        foreach (MeterBatch batch in batches.OrderByDescending(b => b.Count))
        {
            if (assigned >= requested) break;
            int capacity = (int)batch.Count - limits[batch.Id];
            int add = Math.Min(capacity, requested - assigned);
            limits[batch.Id] += add;
            assigned += add;
        }
        return limits;
    }

    private async Task<TaskRunResult> RunPullListenerAsync(PullListenerTask task, DateTimeOffset taskStart, DateTimeOffset end, TestRunState state, CancellationToken ct)
    {
        // Real HES activity comes from SimulatorMetrics: TotalAccepted = connections HES opened,
        // TotalExchanges = DLMS request/response pairs. LiveMeterCount only tracks materialized
        // session objects which barely move — that's why the old readings were all zero.
        SimulatorMetricsSnapshot baseline = _simMetrics.Snapshot(_simMetrics.ActiveInboundExchanges);
        long baseAccepted = baseline.TotalAccepted;
        long baseExchanges = baseline.TotalExchanges;
        long lastAccepted = baseAccepted;
        long lastExchanges = baseExchanges;
        var minuteScores = new List<MinuteScoreRecord>();
        int peakConcurrent = _simMetrics.ActiveInboundExchanges;
        long sumLive = 0;
        int sampleCount = 0;
        var pollInterval = TimeSpan.FromSeconds(5);

        while (!ct.IsCancellationRequested && DateTimeOffset.UtcNow < end)
        {
            try { await Task.Delay(pollInterval, ct); }
            catch (OperationCanceledException) { break; }

            int live = _simMetrics.ActiveInboundExchanges;
            if (live > peakConcurrent) peakConcurrent = live;
            sumLive += live;
            sampleCount++;

            SimulatorMetricsSnapshot poll = _simMetrics.Snapshot(live);
            long connsSoFar = poll.TotalAccepted - baseAccepted;
            long reqsSoFar = poll.TotalExchanges - baseExchanges;
            AddPullMinuteSample(minuteScores, taskStart, DateTimeOffset.UtcNow,
                (int)Math.Min(int.MaxValue, Math.Max(0, poll.TotalExchanges - lastExchanges)),
                (int)Math.Min(int.MaxValue, Math.Max(0, poll.TotalAccepted - lastAccepted)), live);
            lastAccepted = poll.TotalAccepted;
            lastExchanges = poll.TotalExchanges;
            lock (_lock)
                state.LastSummary = $"[{task.DisplayLabel}] {connsSoFar} conn · {reqsSoFar} req (avg {poll.AvgBridgeLatency.TotalMilliseconds:F0}ms) · {live} live";
            Changed?.Invoke();
        }

        SimulatorMetricsSnapshot endSnap = _simMetrics.Snapshot(_simMetrics.ActiveInboundExchanges);
        long deltaAccepted = Math.Max(0, endSnap.TotalAccepted - baseAccepted);
        long deltaExchanges = Math.Max(0, endSnap.TotalExchanges - baseExchanges);
        AddPullMinuteSample(minuteScores, taskStart, DateTimeOffset.UtcNow,
            (int)Math.Min(int.MaxValue, Math.Max(0, endSnap.TotalExchanges - lastExchanges)),
            (int)Math.Min(int.MaxValue, Math.Max(0, endSnap.TotalAccepted - lastAccepted)), _simMetrics.ActiveInboundExchanges);

        double elapsedMin = Math.Max(0.1, (DateTimeOffset.UtcNow - taskStart).TotalMinutes);
        double avgConcurrent = sampleCount > 0 ? (double)sumLive / sampleCount : peakConcurrent;
        double sessionRate = deltaAccepted / elapsedMin;

        // Bridge latency is a lifetime average — for a window-scoped p95-ish figure, use it as-is when
        // the window's traffic dominates; if virtually nothing happened before this task, this is
        // already the window's number. Better than the old 0.
        double avgLatencyMs = endSnap.AvgBridgeLatency.TotalMilliseconds;

        return new TaskRunResult(task,
            pullsReceived: (int)Math.Min(int.MaxValue, deltaAccepted),
            pullsAnswered: (int)Math.Min(int.MaxValue, deltaExchanges),
            pullP95Ms: avgLatencyMs,
            peakConcurrent: peakConcurrent,
            avgConcurrent: avgConcurrent,
            sessionRatePerMin: sessionRate,
            minuteScores: minuteScores);
    }

    private async Task<TickRecord> RunPushTickAsync(int tickNum, string taskId, DateTimeOffset tickStart, IReadOnlyList<int> batchIds, CancellationToken ct, int? maximumMeters = null, IReadOnlyDictionary<int, int>? perBatchLimits = null, bool selectRandomly = false)
    {
        var results = new List<BatchTickResult>();

        foreach (int batchId in batchIds)
        {
            if (ct.IsCancellationRequested) break;

            MeterBatch? batch = _meters.Batches.FirstOrDefault(b => b.Id == batchId);
            if (batch is null) continue;

            var sw = Stopwatch.StartNew();
            BatchTickResult tr;
            try
            {
                int? meterLimit = perBatchLimits is null ? maximumMeters : perBatchLimits.GetValueOrDefault(batchId);
                PushBatchResult r = await _push.PushBatchAsync(batchId, destination: null, ct, meterLimit, selectRandomly);
                sw.Stop();
                tr = new BatchTickResult
                {
                    BatchId = batchId,
                    BatchName = batch.Name,
                    EnvironmentKey = batch.EnvironmentKey,
                    NicType = batch.NicType.ToString(),
                    Total = r.Total,
                    Sent = r.Sent,
                    Failed = r.Failed,
                    DurationMs = sw.ElapsedMilliseconds,
                    Error = r.Ok ? null : r.Error,
                };
            }
            catch (OperationCanceledException)
            {
                // Do not turn an intentional stop into a failed batch. Completed earlier
                // batches remain in this tick and are included in the stopped-run report.
                sw.Stop();
                break;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                sw.Stop();
                tr = new BatchTickResult
                {
                    BatchId = batchId,
                    BatchName = batch.Name,
                    EnvironmentKey = batch.EnvironmentKey,
                    NicType = batch.NicType.ToString(),
                    Total = (int)batch.Count,
                    Failed = (int)batch.Count,
                    DurationMs = sw.ElapsedMilliseconds,
                    Error = ex.Message,
                };
            }

            results.Add(tr);
        }

        return new TickRecord
        {
            TickNumber = tickNum,
            TaskId = taskId,
            TimestampUtc = tickStart,
            TotalSent = results.Sum(r => r.Sent),
            TotalFailed = results.Sum(r => r.Failed),
            Batches = results,
        };
    }

    // ── Report builder ───────────────────────────────────────────────────────────────────────────

    private void Finalize(
        TestRunState state,
        IReadOnlyList<TaskRunResult> taskResults,
        TestPlan plan,
        string runLabel,
        double avgCpu,
        double peakRam,
        DateTimeOffset startUtc,
        SimulatorMetricsSnapshot inboundBaseline,
        bool officialProfileApplied = false)
    {
        DateTimeOffset endUtc = DateTimeOffset.UtcNow;
        TestRunStatus finalStatus;

        lock (_lock)
        {
            finalStatus = state.Status is TestRunStatus.Cancelled or TestRunStatus.Stopped or TestRunStatus.Failed
                ? state.Status
                : TestRunStatus.Completed;
            state.Status = finalStatus;
            state.EndUtc ??= endUtc;
            _cts?.Dispose();
            _cts = null;
        }

        double elapsedMin = Math.Max(1, (endUtc - startUtc).TotalMinutes);
        double systemFactor = ComputeSystemFactor(avgCpu);

        // HES-side delta across the whole run: how much did HES actually touch us?
        SimulatorMetricsSnapshot inboundEnd = _simMetrics.Snapshot(_simMetrics.ActiveInboundExchanges);
        long inboundConns = Math.Max(0, inboundEnd.TotalAccepted - inboundBaseline.TotalAccepted);
        long inboundExchanges = Math.Max(0, inboundEnd.TotalExchanges - inboundBaseline.TotalExchanges);
        double inboundLatencyMs = inboundEnd.AvgBridgeLatency.TotalMilliseconds;

        // Build per-task reports
        var taskReports = taskResults.Select(r => BuildTaskReport(r, elapsedMin)).ToList();

        // Aggregate push metrics
        var allDurations = taskResults
            .SelectMany(r => r.Ticks)
            .SelectMany(t => t.Batches)
            .Select(b => (double)b.DurationMs)
            .OrderBy(d => d)
            .ToList();

        int totalPushed = taskResults.Sum(r => r.Ticks.Sum(t => t.TotalSent));
        int totalFailed = taskResults.Sum(r => r.Ticks.Sum(t => t.TotalFailed));
        int totalExpected = totalPushed + totalFailed;
        double overallSuccess = totalExpected == 0 ? 0 : totalPushed * 100.0 / totalExpected;
        double overallThroughput = totalPushed / elapsedMin;
        double overallMedian = Percentile(allDurations, 50);
        double overallP95 = Percentile(allDurations, 95);

        // Scores are split by traffic direction. Host CPU/RAM and broker latency remain debug
        // telemetry only, so they never alter a benchmark score.
        List<MinuteScoreRecord> minuteScores = BuildMinuteScores(taskResults);
        List<MinuteScoreRecord> pullMinuteScores = taskResults
            .Where(r => r.Task.Type == TestTaskType.PullListener)
            .SelectMany(r => r.MinuteScores)
            .GroupBy(m => m.MinuteStartUtc)
            .Select(g => new MinuteScoreRecord
            {
                MinuteStartUtc = g.Key,
                SuccessfulMeters = g.Sum(m => m.SuccessfulMeters),
                FailedMeters = g.Sum(m => m.FailedMeters),
                PeakConcurrentSessions = g.Max(m => m.PeakConcurrentSessions),
                ConcurrentSessionSampleSum = g.Sum(m => m.ConcurrentSessionSampleSum),
                ConcurrentSessionSamples = g.Sum(m => m.ConcurrentSessionSamples),
            })
            .ToList();
        List<MinuteScoreRecord> pushMinuteScores = BuildMinuteScores(taskResults.Where(r => r.Task.Type != TestTaskType.PullListener));
        MinuteScoreRecord? bestPullMinute = pullMinuteScores.OrderByDescending(PullMinuteScore).FirstOrDefault();
        int pullScore = bestPullMinute is null ? 0 : PullMinuteScore(bestPullMinute);
        int pushScore = pushMinuteScores.Count == 0 ? 0 : pushMinuteScores.Max(m => m.SuccessfulMeters);
        int rawScore = pullScore + pushScore;
        int normalizedScore = rawScore;

        // Per-environment aggregates
        var envKeys = taskResults
            .SelectMany(r => r.Ticks)
            .SelectMany(t => t.Batches)
            .Select(b => b.EnvironmentKey ?? "")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var envReports = envKeys.Select(envKey =>
        {
            var envBatches = taskResults
                .SelectMany(r => r.Ticks)
                .SelectMany(t => t.Batches)
                .Where(b => string.Equals(b.EnvironmentKey ?? "", envKey, StringComparison.OrdinalIgnoreCase))
                .ToList();

            var envDurations = envBatches.Select(b => (double)b.DurationMs).OrderBy(d => d).ToList();
            int eSent = envBatches.Sum(b => b.Sent);
            int eFailed = envBatches.Sum(b => b.Failed);
            int eTotal = eSent + eFailed;
            double ePct = eTotal == 0 ? 0 : eSent * 100.0 / eTotal;
            double eThrough = eSent / elapsedMin;
            double eP95 = Percentile(envDurations, 95);

            // Find representative batch for NIC weight
            string nicStr = envBatches.Select(b => b.NicType).FirstOrDefault() ?? "";
            double nicWeight = NicSuccessWeight(nicStr);
            int envScore = (int)Math.Round(eThrough * nicWeight * (ePct / 100.0) * (1000.0 / (1 + eP95 / 1000.0)) * systemFactor * 100.0);

            return new EnvironmentRunReport
            {
                EnvironmentKey = envKey,
                TotalMetersPushed = eSent,
                TotalMetersFailed = eFailed,
                SuccessRatePct = ePct,
                ThroughputPerMin = eThrough,
                MedianMs = Percentile(envDurations, 50),
                P95Ms = eP95,
                BenchScore = envScore,
            };
        }).ToList();

        var report = new TestRunReport
        {
            RunId = state.RunId,
            RunLabel = runLabel,
            PlanId = state.PlanId,
            PlanName = state.PlanName,
            StartUtc = startUtc,
            EndUtc = endUtc,
            FinalStatus = finalStatus,
            EnvironmentKeys = plan.EnvironmentKeys,
            AvgCpuPct = Math.Round(avgCpu, 1),
            PeakRamMb = Math.Round(peakRam, 0),
            RawBenchScore = rawScore,
            NormalizedBenchScore = normalizedScore,
            PullBenchScore = pullScore,
            PushBenchScore = pushScore,
            MinuteScores = minuteScores,
            TotalMetersPushed = totalPushed,
            TotalMetersFailed = totalFailed,
            OverallSuccessRatePct = overallSuccess,
            OverallThroughputPerMin = overallThroughput,
            OverallMedianMs = overallMedian,
            OverallP95Ms = overallP95,
            TotalInboundConnections = inboundConns,
            TotalInboundExchanges = inboundExchanges,
            AvgInboundLatencyMs = Math.Round(inboundLatencyMs, 1),
            AverageInboundExchangesPerSecond = Math.Round(inboundExchanges / (elapsedMin * 60.0), 2),
            PeakInboundExchangesPerSecond = Math.Round((pullMinuteScores.Count == 0 ? 0 : pullMinuteScores.Max(m => m.SuccessfulMeters)) / 60.0, 2),
            OfficialBenchmarkProfileApplied = officialProfileApplied,
            NetworkDelayLowerMs = officialProfileApplied ? 300 : null,
            NetworkDelayUpperMs = officialProfileApplied ? 500 : null,
            Tasks = taskReports,
            Environments = envReports,
        };

        try { _store.Save(report); }
        catch (Exception ex) { _logger.LogError(ex, "Failed to save report {RunId}", state.RunId); }

        Changed?.Invoke();
        if (finalStatus is TestRunStatus.Completed or TestRunStatus.Stopped) RunCompleted?.Invoke(report);
    }

    private TaskRunReport BuildTaskReport(TaskRunResult r, double elapsedMin)
    {
        var durations = r.Ticks.SelectMany(t => t.Batches).Select(b => (double)b.DurationMs).OrderBy(d => d).ToList();
        int pushed = r.Ticks.Sum(t => t.TotalSent);
        int failed = r.Ticks.Sum(t => t.TotalFailed);
        int total = pushed + failed;
        double successPct = total == 0 ? 0 : pushed * 100.0 / total;
        double throughput = pushed / elapsedMin;
        double p95 = Percentile(durations, 95);

        // score contribution from this task
        double typeMultiplier = r.Task.Type switch
        {
            TestTaskType.PushLoop => 1.0,
            TestTaskType.PullListener => 1.3,
            TestTaskType.BurstPush => 0.9,
            TestTaskType.PartialPush => 0.9,
            _ => 1.0,
        };

        // Flat ×100 scaling — the underlying formula produced 20-something scores; bigger numbers
        // read as scores instead of noise. Nothing else about how runs rank against each other changes.
        const double ScoreScale = 100.0;

        double taskRaw;
        if (r.Task.Type == TestTaskType.PullListener)
        {
            taskRaw = r.PullsAnswered * 1.3 * (r.PullsAnswered > 0 ? (double)r.PullsAnswered / Math.Max(1, r.PullsReceived) : 0) * (1000.0 / (1 + r.PullP95Ms / 1000.0)) * 0.1;
        }
        else
        {
            // Per-batch scoring with NIC weight
            double batchSum = r.Ticks
                .SelectMany(t => t.Batches)
                .GroupBy(b => b.BatchId)
                .Sum(g =>
                {
                    var bDurs = g.Select(b => (double)b.DurationMs).OrderBy(d => d).ToList();
                    int bSent = g.Sum(b => b.Sent);
                    int bFailed = g.Sum(b => b.Failed);
                    int bTotal = bSent + bFailed;
                    double bPct = bTotal == 0 ? 0 : bSent * 100.0 / bTotal;
                    double bThroughput = bSent / elapsedMin;
                    double bP95 = Percentile(bDurs, 95);
                    string nicType = g.First().NicType;
                    double nicW = NicSuccessWeight(nicType);
                    double fleetFactor = Math.Min(2.0, bTotal / 200_000.0);
                    return bThroughput * fleetFactor * nicW * (bPct / 100.0) * (1000.0 / (1 + bP95 / 1000.0));
                });

            double burstFactor = r.Task is BurstPushTask bt ? 1.0 + (bt.BurstCount - 1) * 0.05
                : r.Task is PartialPushTask pt ? 1.0 + (pt.BurstCount - 1) * 0.05 : 1.0;
            taskRaw = batchSum * typeMultiplier * burstFactor;
        }

        taskRaw *= ScoreScale;
        List<MinuteScoreRecord> taskMinutes = BuildMinuteScores(new[] { r });
        int taskBestMinute = r.Task.Type == TestTaskType.PullListener
            ? taskMinutes.DefaultIfEmpty().Max(m => m is null ? 0 : PullMinuteScore(m))
            : taskMinutes.DefaultIfEmpty().Max(m => m?.SuccessfulMeters ?? 0);

        return new TaskRunReport
        {
            TaskId = r.Task.TaskId,
            TaskType = r.Task.Type,
            TaskLabel = r.Task.DisplayLabel,
            OffsetMinutes = r.Task.OffsetMinutes,
            DurationMinutes = r.Task.DurationMinutes,
            TaskScore = taskBestMinute,
            BestMinuteScore = taskBestMinute,
            TotalPushed = pushed,
            TotalFailed = failed,
            SuccessRatePct = successPct,
            ThroughputPerMin = throughput,
            MedianMs = Percentile(durations, 50),
            P95Ms = p95,
            BurstCount = r.BurstCount,
            PullsReceived = r.PullsReceived,
            PullsAnswered = r.PullsAnswered,
            PullSuccessRatePct = r.PullsReceived == 0 ? 0 : r.PullsAnswered * 100.0 / r.PullsReceived,
            PullP95Ms = r.PullP95Ms,
            PeakConcurrentSessions = r.PeakConcurrentSessions,
            AvgConcurrentSessions = Math.Round(r.AvgConcurrentSessions, 1),
            SessionRatePerMin = Math.Round(r.SessionRatePerMin, 2),
            TotalActiveMs = r.Ticks.SelectMany(t => t.Batches).Sum(b => b.DurationMs),
        };
    }

    // ── Scoring helpers ──────────────────────────────────────────────────────────────────────────

    private static List<MinuteScoreRecord> BuildMinuteScores(IEnumerable<TaskRunResult> results)
    {
        var samples = new List<MinuteScoreRecord>();
        foreach (TaskRunResult result in results)
        {
            samples.AddRange(result.MinuteScores);
            foreach (TickRecord tick in result.Ticks)
                AddMinuteScore(samples, tick.TimestampUtc, tick.TotalSent, tick.TotalFailed);
        }

        return samples
            .GroupBy(m => m.MinuteStartUtc)
            .Select(g => new MinuteScoreRecord
            {
                MinuteStartUtc = g.Key,
                SuccessfulMeters = g.Sum(m => m.SuccessfulMeters),
                FailedMeters = g.Sum(m => m.FailedMeters),
                PeakConcurrentSessions = g.Max(m => m.PeakConcurrentSessions),
                ConcurrentSessionSampleSum = g.Sum(m => m.ConcurrentSessionSampleSum),
                ConcurrentSessionSamples = g.Sum(m => m.ConcurrentSessionSamples),
            })
            .OrderBy(m => m.MinuteStartUtc)
            .ToList();
    }

    private OfficialBenchmarkProfile ApplyOfficialProfile()
    {
        var profile = new OfficialBenchmarkProfile(_badComm.Snapshot(), _networkDelay.Current);
        if (!_badComm.TryUpdate(new BadCommConfig { Enabled = false }, out string? error))
            throw new InvalidOperationException($"Could not apply official benchmark profile: {error}");
        if (!_networkDelay.TryUpdate(300, 500))
            throw new InvalidOperationException("Could not apply the official 300-500 ms network delay.");
        return profile;
    }

    private static void AddMinuteScore(List<MinuteScoreRecord> samples, DateTimeOffset timestamp, int successful, int failed)
    {
        DateTimeOffset minute = new(timestamp.Year, timestamp.Month, timestamp.Day, timestamp.Hour, timestamp.Minute, 0, TimeSpan.Zero);
        AddMinuteScoreAt(samples, minute, successful, failed);
    }

    private static void AddMinuteScore(List<MinuteScoreRecord> samples, DateTimeOffset windowStart, DateTimeOffset timestamp, int successful, int failed)
    {
        int minuteOffset = Math.Max(0, (int)Math.Floor((timestamp - windowStart).TotalMinutes));
        AddMinuteScoreAt(samples, windowStart.AddMinutes(minuteOffset), successful, failed);
    }

    private static void AddMinuteScoreAt(List<MinuteScoreRecord> samples, DateTimeOffset minute, int successful, int failed)
    {
        int index = samples.FindIndex(m => m.MinuteStartUtc == minute);
        if (index < 0)
        {
            samples.Add(new MinuteScoreRecord { MinuteStartUtc = minute, SuccessfulMeters = successful, FailedMeters = failed });
            return;
        }
        MinuteScoreRecord old = samples[index];
        samples[index] = new MinuteScoreRecord
        {
            MinuteStartUtc = minute,
            SuccessfulMeters = old.SuccessfulMeters + successful,
            FailedMeters = old.FailedMeters + failed,
            PeakConcurrentSessions = old.PeakConcurrentSessions,
            ConcurrentSessionSampleSum = old.ConcurrentSessionSampleSum,
            ConcurrentSessionSamples = old.ConcurrentSessionSamples,
        };
    }

    private static void AddPullMinuteSample(List<MinuteScoreRecord> samples, DateTimeOffset windowStart, DateTimeOffset timestamp, int successful, int failed, int activeSessions)
    {
        int minuteOffset = Math.Max(0, (int)Math.Floor((timestamp - windowStart).TotalMinutes));
        DateTimeOffset minute = windowStart.AddMinutes(minuteOffset);
        int index = samples.FindIndex(m => m.MinuteStartUtc == minute);
        if (index < 0)
        {
            samples.Add(new MinuteScoreRecord
            {
                MinuteStartUtc = minute, SuccessfulMeters = successful, FailedMeters = failed,
                PeakConcurrentSessions = activeSessions, ConcurrentSessionSampleSum = activeSessions,
                ConcurrentSessionSamples = 1,
            });
            return;
        }

        MinuteScoreRecord old = samples[index];
        samples[index] = new MinuteScoreRecord
        {
            MinuteStartUtc = minute, SuccessfulMeters = old.SuccessfulMeters + successful,
            FailedMeters = old.FailedMeters + failed,
            PeakConcurrentSessions = Math.Max(old.PeakConcurrentSessions, activeSessions),
            ConcurrentSessionSampleSum = old.ConcurrentSessionSampleSum + activeSessions,
            ConcurrentSessionSamples = old.ConcurrentSessionSamples + 1,
        };
    }

    /// <summary>Pull = exchanges + 2 × peak concurrent sessions + average concurrent sessions.</summary>
    private static int PullMinuteScore(MinuteScoreRecord minute) => minute.SuccessfulMeters
        + (2 * minute.PeakConcurrentSessions)
        + (int)Math.Round(minute.AverageConcurrentSessions);

    private static double NicSuccessWeight(string nicType) => nicType switch
    {
        "Tcp4G" => 1.0,
        "Mqtt4G" or "Mqtt4GImg" => 0.65,
        "MqttWirepas" or "MqttKmesh" => 0.60,
        _ => 0.70,
    };

    /// <summary>
    /// System factor: sim running lean (low CPU) means HES is the bottleneck — good score.
    /// Penalty kicks in above 50% CPU, reaching 0.70 floor at 100%.
    /// </summary>
    private static double ComputeSystemFactor(double avgCpuPct) =>
        avgCpuPct < 50 ? 1.0 : Math.Max(0.70, 1.0 - (avgCpuPct - 50) / 167.0);

    private static double Percentile(IReadOnlyList<double> sorted, int pct)
    {
        if (sorted.Count == 0) return 0;
        if (sorted.Count == 1) return sorted[0];
        double rank = pct / 100.0 * (sorted.Count - 1);
        int lo = (int)rank;
        int hi = Math.Min(lo + 1, sorted.Count - 1);
        return sorted[lo] + (rank - lo) * (sorted[hi] - sorted[lo]);
    }

    private static double GetPeakRamMb()
    {
        try { return Process.GetCurrentProcess().PeakWorkingSet64 / (1024.0 * 1024.0); }
        catch { return 0; }
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

    // ── Inner types ──────────────────────────────────────────────────────────────────────────────

    private sealed class TaskRunResult
    {
        public TestTask Task { get; }
        public List<TickRecord> Ticks { get; }
        public int BurstCount { get; }
        public int PullsReceived { get; }
        public int PullsAnswered { get; }
        public double PullP95Ms { get; }
        public int PeakConcurrentSessions { get; }
        public double AvgConcurrentSessions { get; }
        public double SessionRatePerMin { get; }
        public List<MinuteScoreRecord> MinuteScores { get; }

        public TaskRunResult(TestTask task, List<TickRecord>? ticks = null, int burstCount = 0,
            int pullsReceived = 0, int pullsAnswered = 0, double pullP95Ms = 0,
            int peakConcurrent = 0, double avgConcurrent = 0, double sessionRatePerMin = 0,
            List<MinuteScoreRecord>? minuteScores = null)
        {
            Task = task;
            Ticks = ticks ?? new List<TickRecord>();
            BurstCount = burstCount;
            PullsReceived = pullsReceived;
            PullsAnswered = pullsAnswered;
            PullP95Ms = pullP95Ms;
            PeakConcurrentSessions = peakConcurrent;
            AvgConcurrentSessions = avgConcurrent;
            SessionRatePerMin = sessionRatePerMin;
            MinuteScores = minuteScores ?? new List<MinuteScoreRecord>();
        }
    }

    private sealed record OfficialBenchmarkProfile(BadCommConfig BadComm, NetworkDelaySettings.Bounds Delay)
    {
        public void Restore(BadCommSettings badComm, NetworkDelaySettings networkDelay)
        {
            badComm.TryUpdate(BadComm, out _);
            networkDelay.TryUpdate(Delay.LowerMs, Delay.UpperMs);
        }
    }

    /// <summary>Samples process CPU usage on a background thread.</summary>
    private sealed class CpuSampler : IDisposable
    {
        private readonly List<double> _samples = new();
        private readonly System.Threading.Timer _timer;
        private DateTimeOffset _lastTime = DateTimeOffset.UtcNow;
        private TimeSpan _lastCpu;

        public CpuSampler()
        {
            try { _lastCpu = Process.GetCurrentProcess().TotalProcessorTime; }
            catch { _lastCpu = TimeSpan.Zero; }
            _timer = new System.Threading.Timer(_ => Sample(), null, 5000, 5000);
        }

        public double AveragePct
        {
            get { lock (_samples) return _samples.Count == 0 ? 0 : _samples.Average(); }
        }

        private void Sample()
        {
            try
            {
                var proc = Process.GetCurrentProcess();
                var now = DateTimeOffset.UtcNow;
                var cpu = proc.TotalProcessorTime;
                double wallMs = (now - _lastTime).TotalMilliseconds;
                double cpuMs = (cpu - _lastCpu).TotalMilliseconds;
                double pct = wallMs > 0 ? cpuMs / (wallMs * Environment.ProcessorCount) * 100.0 : 0;
                _lastTime = now;
                _lastCpu = cpu;
                lock (_samples) _samples.Add(Math.Min(100, pct));
            }
            catch { }
        }

        public void Dispose() => _timer.Dispose();
    }
}
