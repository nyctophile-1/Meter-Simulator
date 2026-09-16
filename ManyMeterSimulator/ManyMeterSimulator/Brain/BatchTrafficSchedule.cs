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

    public static BatchTrafficWindow Window(DateTimeOffset now, BatchTrafficKind kind, TimeZoneInfo zone)
    {
        var local = TimeZoneInfo.ConvertTime(now, zone).DateTime;
        var start = kind == BatchTrafficKind.Daily ? local.Date
            : new DateTime(local.Year, local.Month, local.Day, local.Hour, local.Minute / 30 * 30, 0);
        if (kind == BatchTrafficKind.Daily && local >= start.AddMinutes(30)) start = start.AddDays(1);
        var utc = new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(start, zone), TimeSpan.Zero);
        return new(utc, utc.AddMinutes(30));
    }

    public static long FirstMeter(long count, int second) =>
        (long)Math.Ceiling(count * (decimal)Math.Clamp(second, 0, WindowSeconds) / WindowSeconds);
}
