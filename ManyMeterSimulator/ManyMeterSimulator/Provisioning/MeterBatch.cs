namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// A contiguous, sequentially-allocated range of meters (IP addresses + meter serial numbers
/// are both derived from the same 1-based index within the range - see MeterRegistry).
/// </summary>
public sealed class MeterBatch
{
    public required int Id { get; init; }

    public required string Name { get; init; }

    /// <summary>
    /// Name of the DLMS template (XML) every meter in this batch is built from
    /// (see TemplateRegistry). Required — a batch with no template can't be simulated.
    /// </summary>
    public required string TemplateName { get; init; }

    /// <summary>1-based index of the first meter in this batch.</summary>
    public required long StartIndex { get; init; }

    public required long Count { get; init; }

    public long EndIndex => StartIndex + Count - 1;

    public BatchStatus Status { get; set; } = BatchStatus.NotStarted;

    public DateTimeOffset CreatedAtUtc { get; } = DateTimeOffset.UtcNow;
}
