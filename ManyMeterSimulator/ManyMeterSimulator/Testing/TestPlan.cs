namespace ManyMeterSimulator.Testing;

public sealed class TestPlan
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..8];
    public string Name { get; set; } = "";
    public bool IsBasePlan { get; init; }

    /// <summary>Only the two supplied standard plans are eligible for a leaderboard.</summary>
    public OfficialTestKind OfficialKind { get; init; }

    public bool IsOfficial => OfficialKind != OfficialTestKind.None;

    /// <summary>HES environments this plan targets (empty = all active environments).</summary>
    public List<string> EnvironmentKeys { get; set; } = new();

    /// <summary>Ordered list of tasks that execute concurrently (each with its own offset).</summary>
    public List<TestTask> Tasks { get; set; } = new();

    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Field names the UI must not let the user change.</summary>
    public HashSet<string> LockedFields { get; set; } = new();

    /// <summary>Session length = latest task end time (offset + duration).</summary>
    public int TotalDurationMinutes =>
        Tasks.Count == 0 ? 0 : Tasks.Max(t => t.EndsAtMinute);

    public string DisplayName => string.IsNullOrWhiteSpace(Name) ? Id : Name;
    public bool IsFieldLocked(string field) => LockedFields.Contains(field);
}

public enum OfficialTestKind { None, Pull, Push }
