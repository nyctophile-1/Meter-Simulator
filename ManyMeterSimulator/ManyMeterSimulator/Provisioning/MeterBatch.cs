using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// A contiguous, sequentially-allocated range of meters (node ids, IP addresses and meter serial
/// numbers are all derived from the same 1-based index within the range - see MeterRegistry).
/// </summary>
public sealed class MeterBatch
{
    public required int Id { get; init; }

    public required string Name { get; init; }

    /// <summary>
    /// The NIC every meter in this batch presents — a real meter's NIC is hardware, so it is fixed
    /// per batch rather than per session. Defaults to <see cref="NicType.Tcp4G"/> so batches
    /// provisioned before NIC types existed keep behaving exactly as they did.
    /// </summary>
    public NicType NicType { get; init; } = NicType.Tcp4G;

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

    // init (not get-only) so a rehydrated batch keeps its ORIGINAL creation time across a
    // restart rather than being stamped with "now" every time the store is reloaded.
    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;
}
