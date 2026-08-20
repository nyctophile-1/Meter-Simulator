using System.Text.Json.Serialization;

namespace ManyMeterSimulator.Testing;

[JsonPolymorphic(TypeDiscriminatorPropertyName = "$type")]
[JsonDerivedType(typeof(PushLoopTask), "push_loop")]
[JsonDerivedType(typeof(PullListenerTask), "pull_listener")]
[JsonDerivedType(typeof(BurstPushTask), "burst_push")]
[JsonDerivedType(typeof(PartialPushTask), "partial_push")]
public abstract class TestTask
{
    public string TaskId { get; init; } = Guid.NewGuid().ToString("N")[..8];
    public abstract TestTaskType Type { get; }
    public string Label { get; set; } = "";
    /// <summary>Minutes after the run starts before this task activates.</summary>
    public int OffsetMinutes { get; set; }
    public int DurationMinutes { get; set; } = 15;
    /// <summary>Push target selected on the task. Pull listeners leave this empty.</summary>
    public string? EnvironmentKey { get; set; }

    public string DisplayLabel => string.IsNullOrWhiteSpace(Label) ? Type switch
    {
        TestTaskType.PushLoop => "Push Loop",
        TestTaskType.PullListener => "Pull Listener",
        TestTaskType.BurstPush => "All Push",
        TestTaskType.PartialPush => "Partial Push",
        _ => Type.ToString(),
    } : Label;
    public int EndsAtMinute => OffsetMinutes + DurationMinutes;
}

public enum TestTaskType { PushLoop, PullListener, BurstPush, PartialPush }

public enum PartialPushMode { Count, Percentage }

/// <summary>Periodic push loop — repeats every <see cref="PushIntervalSec"/> for the task's duration.</summary>
public sealed class PushLoopTask : TestTask
{
    public override TestTaskType Type => TestTaskType.PushLoop;
    public int PushIntervalSec { get; set; } = 300;
    public List<int> BatchIds { get; set; } = new();
}

/// <summary>Passive listener — monitors inbound TCP pull sessions during its duration window.</summary>
public sealed class PullListenerTask : TestTask
{
    public override TestTaskType Type => TestTaskType.PullListener;
    public List<int> BatchIds { get; set; } = new();
    // No extra config — uses the existing TCP listener socket.
}

/// <summary>Back-to-back burst pushes — sends <see cref="BurstCount"/> full-fleet pushes consecutively.</summary>
public sealed class BurstPushTask : TestTask
{
    public override TestTaskType Type => TestTaskType.BurstPush;
    public int BurstCount { get; set; } = 3;
    public List<int> BatchIds { get; set; } = new();
    public int? MetersPerBatch { get; set; }
}

/// <summary>Back-to-back pushes over a random subset of the selected batches.</summary>
public sealed class PartialPushTask : TestTask
{
    public override TestTaskType Type => TestTaskType.PartialPush;
    public int BurstCount { get; set; } = 1;
    public List<int> BatchIds { get; set; } = new();
    public PartialPushMode Mode { get; set; } = PartialPushMode.Count;
    /// <summary>Exact meter total across all selected batches when <see cref="Mode"/> is Count.</summary>
    public int MeterCount { get; set; } = 1_000;
    /// <summary>Random share from every selected batch when <see cref="Mode"/> is Percentage.</summary>
    public double Percentage { get; set; } = 10;
}
