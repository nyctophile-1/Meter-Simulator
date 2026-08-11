using System.Diagnostics;
using ManyMeterSimulator.Brain;
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
        MeterSessionManager sessions,
        TestRunStore store,
        ILogger<TestRunEngine> logger)
    {
        _meters = meters;
        _network = network;
        _push = push;
        _sessions = sessions;
        _store = store;
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
        lock (_lock)
        {
            if (IsActive) throw new InvalidOperationException("A test run is already active. Cancel it first.");

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

    public void Cancel()
    {
        CancellationTokenSource? cts;
        lock (_lock)
        {
            cts = _cts;
            if (_active is { Status: TestRunStatus.Scheduled or TestRunStatus.Running } s)
            {
                s.Status = TestRunStatus.Cancelled;
                s.EndUtc = DateTimeOffset.UtcNow;
            }
        }

        cts?.Cancel();
        Changed?.Invoke();
    }

    // ── Run loop ────────────────────────────────────────────────────────────────────────────────

    private async Task RunAsync(TestPlan plan, string runLabel, DateTimeOffset startAt, TestRunState state, CancellationToken ct)
    {
        // Wait for scheduled start
        TimeSpan waitFor = startAt - DateTimeOffset.UtcNow;
        if (waitFor > TimeSpan.FromSeconds(2))
        {
            try { await Task.Delay(waitFor, ct); }
            catch (OperationCanceledException) { Finalize(state, Array.Empty<TaskRunResult>(), plan, runLabel, 0, 0, startAt); return; }
        }

        DateTimeOffset actualStart = DateTimeOffset.UtcNow;
        lock (_lock)
        {
            state.Status = TestRunStatus.Running;
            state.ActualStartUtc = actualStart;
        }
        Changed?.Invoke();

        // Launch CPU sampler + all tasks concurrently
        using var cpuSampler = new CpuSampler();
        var taskTasks = plan.Tasks.Select(task => RunTaskAsync(task, actualStart, state, ct)).ToList();
        TaskRunResult[] taskResults = await Task.WhenAll(taskTasks);

        double avgCpu = cpuSampler.AveragePct;
        double peakRam = GetPeakRamMb();

        Finalize(state, taskResults, plan, runLabel, avgCpu, peakRam, actualStart);
    }

    private async Task<TaskRunResult> RunTaskAsync(TestTask task, DateTimeOffset runStart, TestRunState state, CancellationToken ct)
    {
        // Respect offset
        if (task.OffsetMinutes > 0)
        {
            DateTimeOffset taskStart = runStart.AddMinutes(task.OffsetMinutes);
            TimeSpan wait = taskStart - DateTimeOffset.UtcNow;
            if (wait > TimeSpan.Zero)
            {
                try { await Task.Delay(wait, ct); }
                catch (OperationCanceledException) { return new TaskRunResult(task); }
            }
        }

        DateTimeOffset end = DateTimeOffset.UtcNow.AddMinutes(task.DurationMinutes);

        return task switch
        {
            PushLoopTask loop => await RunPushLoopAsync(loop, end, state, ct),
            PullListenerTask pull => await RunPullListenerAsync(pull, end, state, ct),
            BurstPushTask burst => await RunBurstPushAsync(burst, end, state, ct),
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

        for (int burst = 1; burst <= task.BurstCount && !ct.IsCancellationRequested && DateTimeOffset.UtcNow < end; burst++)
        {
            DateTimeOffset tickStart = DateTimeOffset.UtcNow;
            TickRecord tick = await RunPushTickAsync(burst, task.TaskId, tickStart, task.BatchIds, ct);
            ticks.Add(tick);

            lock (_lock)
                state.LastSummary = $"[{task.DisplayLabel}] burst {burst}/{task.BurstCount}: {tick.TotalSent} sent";
            Changed?.Invoke();
        }

        return new TaskRunResult(task, ticks, task.BurstCount);
    }

    private async Task<TaskRunResult> RunPullListenerAsync(PullListenerTask task, DateTimeOffset end, TestRunState state, CancellationToken ct)
    {
        // Monitor inbound TCP sessions during the window as a proxy for pull activity.
        int baselineSessions = _sessions.LiveMeterCount;
        int peakSessions = baselineSessions;
        int prevLive = baselineSessions;
        long sumLive = 0;
        int sampleCount = 0;
        long newSessionsOpened = 0;
        DateTimeOffset taskStart = DateTimeOffset.UtcNow;
        var pollInterval = TimeSpan.FromSeconds(5);

        while (!ct.IsCancellationRequested && DateTimeOffset.UtcNow < end)
        {
            try { await Task.Delay(pollInterval, ct); }
            catch (OperationCanceledException) { break; }

            int live = _sessions.LiveMeterCount;
            if (live > peakSessions) peakSessions = live;
            sumLive += live;
            sampleCount++;
            // count sessions that newly connected since last sample
            if (live > prevLive) newSessionsOpened += live - prevLive;
            prevLive = live;

            lock (_lock)
                state.LastSummary = $"[{task.DisplayLabel}] {live} active sessions (peak: {peakSessions})";
            Changed?.Invoke();
        }

        double elapsedMin = Math.Max(0.1, (DateTimeOffset.UtcNow - taskStart).TotalMinutes);
        double avgConcurrent = sampleCount > 0 ? (double)sumLive / sampleCount : baselineSessions;
        double sessionRate = newSessionsOpened / elapsedMin;

        int pullsReceived = Math.Max(0, peakSessions - baselineSessions);
        return new TaskRunResult(task,
            pullsReceived: pullsReceived,
            pullsAnswered: pullsReceived,
            peakConcurrent: peakSessions,
            avgConcurrent: avgConcurrent,
            sessionRatePerMin: sessionRate);
    }

    private async Task<TickRecord> RunPushTickAsync(int tickNum, string taskId, DateTimeOffset tickStart, IReadOnlyList<int> batchIds, CancellationToken ct)
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
                PushBatchResult r = await _push.PushBatchAsync(batchId, destination: null, ct);
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
        DateTimeOffset startUtc)
    {
        DateTimeOffset endUtc = DateTimeOffset.UtcNow;
        TestRunStatus finalStatus;

        lock (_lock)
        {
            finalStatus = state.Status is TestRunStatus.Cancelled or TestRunStatus.Failed
                ? state.Status
                : TestRunStatus.Completed;
            state.Status = finalStatus;
            state.EndUtc ??= endUtc;
            _cts?.Dispose();
            _cts = null;
        }

        double elapsedMin = Math.Max(1, (endUtc - startUtc).TotalMinutes);
        double systemFactor = ComputeSystemFactor(avgCpu);

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

        int rawScore = (int)Math.Round(taskReports.Sum(t => t.TaskScore) * systemFactor);
        int normalizedScore = taskReports.Count == 0 ? 0 : rawScore / taskReports.Count;

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
            TotalMetersPushed = totalPushed,
            TotalMetersFailed = totalFailed,
            OverallSuccessRatePct = overallSuccess,
            OverallThroughputPerMin = overallThroughput,
            OverallMedianMs = overallMedian,
            OverallP95Ms = overallP95,
            Tasks = taskReports,
            Environments = envReports,
        };

        try { _store.Save(report); }
        catch (Exception ex) { _logger.LogError(ex, "Failed to save report {RunId}", state.RunId); }

        Changed?.Invoke();
        if (finalStatus == TestRunStatus.Completed) RunCompleted?.Invoke(report);
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

            double burstFactor = r.Task is BurstPushTask bt ? 1.0 + (bt.BurstCount - 1) * 0.05 : 1.0;
            taskRaw = batchSum * typeMultiplier * burstFactor;
        }

        taskRaw *= ScoreScale;

        return new TaskRunReport
        {
            TaskId = r.Task.TaskId,
            TaskType = r.Task.Type,
            TaskLabel = r.Task.DisplayLabel,
            OffsetMinutes = r.Task.OffsetMinutes,
            DurationMinutes = r.Task.DurationMinutes,
            TaskScore = (int)Math.Round(taskRaw),
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

        public TaskRunResult(TestTask task, List<TickRecord>? ticks = null, int burstCount = 0,
            int pullsReceived = 0, int pullsAnswered = 0, double pullP95Ms = 0,
            int peakConcurrent = 0, double avgConcurrent = 0, double sessionRatePerMin = 0)
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
