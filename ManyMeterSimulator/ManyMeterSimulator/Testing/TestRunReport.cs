namespace ManyMeterSimulator.Testing;

/// <summary>
/// Persisted result of one completed test run. Everything the Results viewer needs lives here.
/// </summary>
public sealed class TestRunReport
{
    public string RunId { get; init; } = "";
    public string RunLabel { get; init; } = "";
    public string PlanId { get; init; } = "";
    public string PlanName { get; init; } = "";
    public DateTimeOffset StartUtc { get; init; }
    public DateTimeOffset EndUtc { get; init; }
    public TestRunStatus FinalStatus { get; init; }
    public List<string> EnvironmentKeys { get; init; } = new();

    // System metrics captured during run
    public double AvgCpuPct { get; init; }
    public double PeakRamMb { get; init; }

    // Scores
    /// <summary>Sum of all task scores. More tasks = higher ceiling.</summary>
    public int RawBenchScore { get; init; }
    /// <summary>RawBenchScore / task count — comparable across plans of different size.</summary>
    public int NormalizedBenchScore { get; init; }

    // Convenience alias for existing Results page code
    public int BenchScore => RawBenchScore;

    // Fleet-wide push aggregates
    public int TotalMetersPushed { get; init; }
    public int TotalMetersFailed { get; init; }
    public double OverallSuccessRatePct { get; init; }
    public double OverallThroughputPerMin { get; init; }
    public double OverallMedianMs { get; init; }
    public double OverallP95Ms { get; init; }

    // Per-task breakdown
    public List<TaskRunReport> Tasks { get; init; } = new();

    // Per-environment (aggregated across tasks)
    public List<EnvironmentRunReport> Environments { get; init; } = new();
}

public sealed class TaskRunReport
{
    public string TaskId { get; init; } = "";
    public TestTaskType TaskType { get; init; }
    public string TaskLabel { get; init; } = "";
    public int OffsetMinutes { get; init; }
    public int DurationMinutes { get; init; }
    public int TaskScore { get; init; }

    // Push metrics (PushLoop, BurstPush)
    public int TotalPushed { get; init; }
    public int TotalFailed { get; init; }
    public double SuccessRatePct { get; init; }
    public double ThroughputPerMin { get; init; }
    public double MedianMs { get; init; }
    public double P95Ms { get; init; }
    public int BurstCount { get; init; }

    // Pull metrics (PullListener)
    public int PullsReceived { get; init; }
    public int PullsAnswered { get; init; }
    public double PullSuccessRatePct { get; init; }
    public double PullP95Ms { get; init; }
    public int PeakConcurrentSessions { get; init; }
    public double AvgConcurrentSessions { get; init; }
    public double SessionRatePerMin { get; init; }

    // Push metrics extra
    public long TotalActiveMs { get; init; }
}

public sealed class EnvironmentRunReport
{
    public string EnvironmentKey { get; init; } = "";
    public int TotalMetersPushed { get; init; }
    public int TotalMetersFailed { get; init; }
    public double SuccessRatePct { get; init; }
    public double ThroughputPerMin { get; init; }
    public double MedianMs { get; init; }
    public double P95Ms { get; init; }
    public int BenchScore { get; init; }
}

// ── Tick-level records ──────────────────────────────────────────────────────────────────────────

public sealed class TickRecord
{
    public int TickNumber { get; init; }
    public string TaskId { get; init; } = "";
    public DateTimeOffset TimestampUtc { get; init; }
    public int TotalSent { get; init; }
    public int TotalFailed { get; init; }
    public List<BatchTickResult> Batches { get; init; } = new();
}

public sealed class BatchTickResult
{
    public int BatchId { get; init; }
    public string BatchName { get; init; } = "";
    public string? EnvironmentKey { get; init; }
    public string NicType { get; init; } = "";
    public int Total { get; init; }
    public int Sent { get; init; }
    public int Failed { get; init; }
    public long DurationMs { get; init; }
    public string? Error { get; init; }
}

public sealed class BatchRunReport
{
    public int BatchId { get; init; }
    public string BatchName { get; init; } = "";
    public string NicType { get; init; } = "";
    public int MeterCount { get; init; }
    public string? EnvironmentKey { get; init; }
    public int TotalMetersPushed { get; init; }
    public int TotalMetersFailed { get; init; }
    public double SuccessRatePct { get; init; }
    public double MedianMs { get; init; }
    public double P95Ms { get; init; }
}

public enum TestRunStatus { Scheduled, Running, Completed, Failed, Cancelled }

public sealed class TestRunState
{
    public string RunId { get; init; } = "";
    public string PlanId { get; init; } = "";
    public string PlanName { get; init; } = "";
    public string RunLabel { get; init; } = "";
    public TestRunStatus Status { get; set; }
    public DateTimeOffset ScheduledStartUtc { get; init; }
    public DateTimeOffset? ActualStartUtc { get; set; }
    public int TotalDurationMinutes { get; init; }
    public string? LastSummary { get; set; }

    public double ElapsedPct
    {
        get
        {
            if (ActualStartUtc is null || TotalDurationMinutes <= 0) return 0;
            return Math.Min(100,
                (DateTimeOffset.UtcNow - ActualStartUtc.Value).TotalMinutes * 100.0 / TotalDurationMinutes);
        }
    }
}
