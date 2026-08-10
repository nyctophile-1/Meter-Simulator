namespace ManyMeterSimulator.Testing;

/// <summary>
/// A named benchmark configuration: which environments to target, which batches to push from,
/// how often to push, and how long to collect. The base plan ships with locked push interval and
/// collection duration so every team measures on the same cadence.
/// </summary>
public sealed class TestPlan
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..8];
    public string Name { get; set; } = "";
    public bool IsBasePlan { get; init; }

    /// <summary>How often to fire a push during the run. Locked to 300 s on the base plan.</summary>
    public int PushIntervalSec { get; set; } = 300;

    /// <summary>Total collection window. Locked to 15 min on the base plan.</summary>
    public int CollectionDurationMin { get; set; } = 15;

    /// <summary>HES environment keys this plan targets (empty = all enabled environments).</summary>
    public List<string> EnvironmentKeys { get; set; } = new();

    /// <summary>Batch IDs to push from. Stored as ints (per-deployment); translated to names on export.</summary>
    public List<int> BatchIds { get; set; } = new();

    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Field names (C# property names) the UI must not let the user change.</summary>
    public HashSet<string> LockedFields { get; set; } = new();

    public bool IsFieldLocked(string field) => LockedFields.Contains(field);
    public string DisplayName => string.IsNullOrWhiteSpace(Name) ? Id : Name;
}
