namespace ManyMeterSimulator.Testing;

/// <summary>
/// Persisted result of one completed (or cancelled) test run. Everything the Results viewer and
/// the side-by-side comparison need lives in this one record — no second lookup required.
/// </summary>
public sealed class TestRunReport
{
    public string RunId { get; init; } = "";
    public string PlanId { get; init; } = "";
    public string PlanName { get; init; } = "";
    public DateTimeOffset StartUtc { get; init; }
    public DateTimeOffset EndUtc { get; init; }
    public TestRunStatus FinalStatus { get; init; }
    public int PushIntervalSec { get; init; }
    public int CollectionDurationMin { get; init; }
    public List<string> EnvironmentKeys { get; init; } = new();

    // ── Fleet-wide aggregates ────────────────────────────────────────────────────────────────────
    public int TotalTicks { get; init; }
    public int TotalMetersPushed { get; init; }     // actually sent
    public int TotalMetersExpected { get; init; }   // attempted
    public int TotalMetersFailed { get; init; }
    public double SuccessRatePct { get; init; }

    /// <summary>Successfully sent meters per minute of collection time.</summary>
    public double ThroughputPerMin { get; init; }

    public double MedianPushDurationMs { get; init; }
    public double P95PushDurationMs { get; init; }

    /// <summary>
    /// Composite benchmark score.
    /// Formula: round( (TotalMetersPushed / ElapsedMin) / (1 + P95Ms/1000) × SuccessRatePct )
    /// Higher = faster HES with fewer failures and lower tail latency.
    /// </summary>
    public int BenchScore { get; init; }

    // ── Per-environment breakdown ────────────────────────────────────────────────────────────────
    public List<EnvironmentRunReport> Environments { get; init; } = new();

    // ── Raw tick log ────────────────────────────────────────────────────────────────────────────
    public List<TickRecord> Ticks { get; init; } = new();
}

public sealed class EnvironmentRunReport
{
    public string EnvironmentKey { get; init; } = "";
    public int TotalMetersPushed { get; init; }
    public int TotalMetersExpected { get; init; }
    public int TotalMetersFailed { get; init; }
    public double SuccessRatePct { get; init; }
    public double ThroughputPerMin { get; init; }
    public double MedianPushDurationMs { get; init; }
    public double P95PushDurationMs { get; init; }
    public int BenchScore { get; init; }
    public List<BatchRunReport> Batches { get; init; } = new();
}

public sealed class BatchRunReport
{
    public int BatchId { get; init; }
    public string BatchName { get; init; } = "";
    public string NicType { get; init; } = "";
    public int MeterCount { get; init; }
    public string? EnvironmentKey { get; init; }
    public int TotalMetersPushed { get; init; }
    public int TotalMetersExpected { get; init; }
    public int TotalMetersFailed { get; init; }
    public double SuccessRatePct { get; init; }
    public double MedianPushDurationMs { get; init; }
    public double P95PushDurationMs { get; init; }
}

public sealed class TickRecord
{
    public int TickNumber { get; init; }
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
    public int Total { get; init; }
    public int Sent { get; init; }
    public int Failed { get; init; }
    public long DurationMs { get; init; }
    public string? Error { get; init; }
}

public enum TestRunStatus { Scheduled, Running, Completed, Failed, Cancelled }

/// <summary>Live view of an in-progress run — what the Testing page renders while waiting.</summary>
public sealed class TestRunState
{
    public string RunId { get; init; } = "";
    public string PlanId { get; init; } = "";
    public string PlanName { get; init; } = "";
    public TestRunStatus Status { get; set; }
    public DateTimeOffset ScheduledStartUtc { get; init; }
    public DateTimeOffset? ActualStartUtc { get; set; }
    public int ExpectedTicks { get; init; }
    public int CompletedTicks { get; set; }
    public DateTimeOffset? NextTickUtc { get; set; }
    public string? LastTickSummary { get; set; }
    public double ElapsedPct => ExpectedTicks == 0 ? 0 : Math.Min(100, CompletedTicks * 100.0 / ExpectedTicks);
}
