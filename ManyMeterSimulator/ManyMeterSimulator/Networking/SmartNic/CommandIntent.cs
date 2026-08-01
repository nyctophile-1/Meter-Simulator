using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>
/// What HES asked for, stripped of every transport detail.
///
/// This is the seam that makes the smart NIC reusable: RF2 Wirepas produces one of these today,
/// and a future custom-Kmesh variant would produce the same thing from a completely different
/// envelope. Everything downstream — the DLMS conversation, the response packing — is written
/// against this and never learns which radio it came from.
/// </summary>
public sealed record CommandIntent(
    MeterRef Meter,
    CustomCommandType Command,
    CustomDataSelector Selector,
    uint ValueFrom,
    uint ValueTo)
{
    /// <summary>
    /// Correlation the codec must echo back. Opaque here — RF2 carries a 2- or 4-byte frame id
    /// depending on the meter template.
    /// </summary>
    public uint FrameId { get; init; }

    /// <summary>
    /// <see cref="ValueFrom"/>/<see cref="ValueTo"/> as UTC, for the range-based commands. HES
    /// sends unix seconds; whether they are UTC or IST-shifted is per-command in the HES source,
    /// so the codec decides and this is the resolved value.
    /// </summary>
    public DateTimeOffset? RangeStart { get; init; }

    public DateTimeOffset? RangeEnd { get; init; }

    /// <summary>Anything the codec needs handed back at pack time (gateway, sink, endpoints).</summary>
    public object? CodecState { get; init; }
}

/// <summary>
/// The command types the smart NIC understands, named after HES's own CommandTypeEnum so the two
/// stay legible against each other. Deliberately a small subset: only what is actually simulated.
/// The wire carries HES's numeric value, which the codec maps here.
/// </summary>
public enum CustomCommandType
{
    Unknown = 0,
    GetBlockLoadProfile,
    GetInstantaneousProfile,
    GetDailyLoadProfile,
    GetBillingProfile,
    GetNamePlate,
    SyncRtc,
}

/// <summary>
/// HES's CustomCommandDataSelector — whether the command is a plain read, a read over a range, or
/// a write carrying data.
/// </summary>
public enum CustomDataSelector
{
    Get = 0,
    GetWithDateRange,
    GetWithEntryRange,
    SetWithData,
}

/// <summary>
/// What the smart NIC read out of the meter, before it is packed into a manufacturer's binary
/// layout. Transport- and format-agnostic on purpose: the packer turns this into bytes using the
/// per-template data model, and a different NIC family would pack the same result differently.
/// </summary>
public sealed record MeterReadResult(CommandIntent Intent, IReadOnlyList<MeterReadRow> Rows)
{
    public bool IsSuccess { get; init; } = true;

    /// <summary>Set when the DLMS conversation failed; the codec turns this into the NIC's error form.</summary>
    public string? Error { get; init; }

    public static MeterReadResult Failed(CommandIntent intent, string error) =>
        new(intent, Array.Empty<MeterReadRow>()) { IsSuccess = false, Error = error };
}

/// <summary>
/// One row of a profile read, or a single row holding scalars for a non-profile command. Values
/// are keyed by OBIS so the packer can lay them out in whatever order the template dictates
/// without the reader knowing that order.
/// </summary>
public sealed record MeterReadRow(DateTimeOffset? Timestamp, IReadOnlyDictionary<string, object?> Values);
