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
    /// HES's meter-template id — a DIFFERENT thing from <see cref="TemplateName"/>.
    ///
    /// <see cref="TemplateName"/> is the DLMS XML: what objects and values the meter HAS. This is
    /// HES's data model: how those values are PACKAGED on the wire, for all four combinations
    /// (DLMS pull/push, custom pull/push). It selects the row in HES's MeterTemplate table, which
    /// in turn selects the ordered field lists in MeterTemplateDetail.
    ///
    /// Needed only for a NIC's CUSTOM channel — today that is Wirepas endpoint 13, where the NIC
    /// builds the response itself. The plain DLMS channel needs none of this, so it stays optional:
    /// the same Wirepas meter answers DLMS on endpoint 3 with no data model at all, and requiring
    /// one would block a valid DLMS-only setup.
    /// </summary>
    public int? HesTemplateId { get; init; }

    /// <summary>
    /// Name of the DLMS template (XML) every meter in this batch is built from
    /// (see TemplateRegistry). Required — a batch with no template can't be simulated.
    /// </summary>
    public required string TemplateName { get; init; }

    /// <summary>1-based index of the first meter in this batch.</summary>
    public required long StartIndex { get; init; }

    public required long Count { get; init; }

    public long EndIndex => StartIndex + Count - 1;

    /// <summary>
    /// Key of the MQTT broker in the network registry this batch's meters talk through, or null for
    /// **unbound** — a legal state meaning "connected to nothing" (network_registry.md §3.2).
    ///
    /// An unbound MQTT batch contributes no broker binding, so it is never reached. That is exactly
    /// the symptom nobody can diagnose from silence, so it is called out explicitly in the startup
    /// NIC plan and on the batch row rather than left to be inferred.
    ///
    /// Meaningless for <see cref="NicType.Tcp4G"/>, whose inbound sessions are broker-agnostic.
    /// Settable (like <see cref="Status"/>) because rebinding is an admin action on a live batch.
    /// </summary>
    public string? BrokerKey { get; set; }

    /// <summary>
    /// Key of the HES TCP push listener this batch's meters push to, or null for unbound.
    ///
    /// Only used in the OUTBOUND push direction, and only by <see cref="NicType.Tcp4G"/> — inbound
    /// TCP needs no registry at all. Null is benign here: pulls keep working, and push simply has
    /// no destination until one is assigned.
    /// </summary>
    public string? PushTargetKey { get; set; }

    public BatchStatus Status { get; set; } = BatchStatus.NotStarted;

    // init (not get-only) so a rehydrated batch keeps its ORIGINAL creation time across a
    // restart rather than being stamped with "now" every time the store is reloaded.
    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;
}
