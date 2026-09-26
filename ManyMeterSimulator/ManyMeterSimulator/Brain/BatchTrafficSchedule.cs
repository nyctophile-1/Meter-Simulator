using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Brain;

public sealed class BatchTrafficOptions
{
    public string TimeZoneId { get; set; } = "Asia/Kolkata";
    public int MaxConcurrency { get; set; } = 32;
}

public readonly record struct BatchTrafficWindow(DateTimeOffset Start, DateTimeOffset End);

public static class BatchTrafficSchedule
{
    public const int WindowSeconds = 1800;

    public static BatchTrafficWindow Window(DateTimeOffset now, BatchTrafficKind kind, TimeZoneInfo zone, int blockPeriodSeconds = WindowSeconds)
    {
        var local = TimeZoneInfo.ConvertTime(now, zone).DateTime;
        var start = kind == BatchTrafficKind.Daily ? local.Date
            : kind == BatchTrafficKind.Billing ? new DateTime(local.Year, local.Month, 1)
            : kind == BatchTrafficKind.BlockLoad ? NextBlockBoundary(local, blockPeriodSeconds)
            : new DateTime(local.Year, local.Month, local.Day, local.Hour, local.Minute / 30 * 30, 0);
        if (kind == BatchTrafficKind.Daily && local >= start.AddMinutes(30)) start = start.AddDays(1);
        if (kind == BatchTrafficKind.Billing && local >= start.AddMinutes(30))
        {
            var next = start.AddMonths(1);
            start = new DateTime(next.Year, next.Month, 1);
        }
        var utc = new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(start, zone), TimeSpan.Zero);
        return new(utc, utc.AddSeconds(kind == BatchTrafficKind.BlockLoad ? blockPeriodSeconds : WindowSeconds));
    }

    private static DateTime NextBlockBoundary(DateTime local, int periodSeconds)
    {
        if (periodSeconds <= 0 || 86400 % periodSeconds != 0)
            throw new ArgumentOutOfRangeException(nameof(periodSeconds), "Block Load capture period must divide one day.");
        long ticks = TimeSpan.FromSeconds(periodSeconds).Ticks;
        long elapsed = local.TimeOfDay.Ticks;
        long next = (elapsed + ticks - 1) / ticks * ticks;
        return local.Date.AddTicks(next);
    }

    public static long FirstMeter(long count, int second) =>
        (long)Math.Ceiling(count * (decimal)Math.Clamp(second, 0, WindowSeconds) / WindowSeconds);
}
