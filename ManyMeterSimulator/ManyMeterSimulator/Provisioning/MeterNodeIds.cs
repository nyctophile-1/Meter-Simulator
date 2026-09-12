using System.Globalization;

namespace ManyMeterSimulator.Provisioning;

/// <summary>MAYA's reserved node range, independent of serial numbers and other simulators.</summary>
public static class MeterNodeIds
{
    public const long Offset = 1_000_000_000;

    public static uint Value(long index)
    {
        if (index is < 1 or > MeterRegistry.MaxIndex)
            throw new ArgumentOutOfRangeException(nameof(index));
        return checked((uint)(Offset + index));
    }

    public static string Format(long index) => Value(index).ToString(CultureInfo.InvariantCulture);

    public static bool TryGetIndex(string? nodeId, out long index)
    {
        index = 0;
        if (!long.TryParse(nodeId, NumberStyles.None, CultureInfo.InvariantCulture, out long value)
            || value <= Offset || value > Offset + MeterRegistry.MaxIndex)
            return false;
        index = value - Offset;
        return true;
    }
}
