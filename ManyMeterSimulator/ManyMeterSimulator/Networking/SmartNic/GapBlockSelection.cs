using System.Numerics;

namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>HES serializes exactly 32 bits; character zero is the least-significant bit.</summary>
public sealed record GapBlockSelection(DateTimeOffset From, int PeriodMinutes, uint Mask)
{
    public DateTimeOffset Timestamp(int bit) => bit is >= 0 and < 32
        ? From.AddMinutes(bit * PeriodMinutes) : throw new ArgumentOutOfRangeException(nameof(bit));

    public bool Includes(int bit) => bit is >= 0 and < 32
        ? (Mask & (1u << bit)) != 0 : throw new ArgumentOutOfRangeException(nameof(bit));

    public static GapBlockSelection Create(CustomPullInbound inbound, CustomPullOptions options)
    {
        if (inbound.Intent.Command != CustomCommandType.GRBlockLoadProfile || inbound.Intent.Selector != CustomDataSelector.GetWithDateRange)
            throw new ArgumentException("GRBlockLoad requires a FromDate and bitmap, carried by selector 5.");
        int period = options.BlockPeriodMinutesByTemplate.GetValueOrDefault(inbound.Protocol.HesTemplateId, options.BlockPeriodMinutes);
        if (period is not (15 or 30)) throw new InvalidOperationException("Generated block period must be 15 or 30 minutes.");
        int limit = inbound.Protocol.WireProfile == CustomPullWireProfile.NewHeader ? 15 : 255;
        int selected = BitOperations.PopCount(inbound.Intent.ValueTo);
        if (selected > limit)
            throw new NotSupportedException($"This HES header supports at most {limit} selected rows in one command response; split the bitmap across separate commands.");
        if (selected > options.MaxProfileRows) throw new InvalidOperationException("GR row limit exceeded.");
        long epoch = inbound.Intent.ValueFrom - options.BlockRequestOffsetMinutes * 60L;
        if (epoch % (period * 60) != 0) throw new ArgumentException("GR FromDate must fall on a configured block boundary.");
        // FromDate is the timestamp of bit zero; ValueTo is never interpreted as an end date.
        return new GapBlockSelection(DateTimeOffset.FromUnixTimeSeconds(epoch), period, inbound.Intent.ValueTo);
    }
}
