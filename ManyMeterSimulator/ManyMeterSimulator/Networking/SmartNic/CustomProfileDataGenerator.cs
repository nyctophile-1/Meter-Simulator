using Gurux.DLMS;

namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>Deterministic simulation values in engineering units, independent of the XML snapshot.</summary>
public static class CustomProfileDataGenerator
{
    public static int EventId(CustomCommandType command) => command switch
    {
        CustomCommandType.GetVoltageEventProfile => 1,
        CustomCommandType.GetCurrentEventProfile => 51,
        CustomCommandType.GetPowerEventProfile => 101,
        CustomCommandType.GetTransactionEventProfile => 151,
        CustomCommandType.GetOtherEventProfile => 201,
        CustomCommandType.GetNonRollOverEventProfile => 251,
        CustomCommandType.GetControlEventProfile => 301,
        CustomCommandType.GetDiData => 889,
        _ => 0,
    };

    public static IReadOnlyList<DateTimeOffset> SelectTimestamps(CommandIntent intent, DateTimeOffset now, CustomPullOptions options)
    {
        if (intent.Command == CustomCommandType.GetInstantaneousProfile) return [now];
        if (intent.Selector == CustomDataSelector.GetWithDateRange) return GenerateDateRange(intent, now, options);
        var times = new List<DateTimeOffset>();
        var local = now.ToOffset(TimeSpan.FromMinutes(options.ResponseTimestampOffsetMinutes));
        var midnight = new DateTimeOffset(local.Year, local.Month, local.Day, 0, 0, 0, local.Offset);
        if (intent.Command == CustomCommandType.GetBillingProfile)
        {
            var month = new DateTimeOffset(local.Year, local.Month, 1, 0, 0, 0, local.Offset);
            for (int i = 11; i >= 0; i--) times.Add(month.AddMonths(-i).ToUniversalTime());
        }
        else if (intent.Command == CustomCommandType.GetDailyLoadProfile)
        {
            for (int i = 29; i >= 0; i--) times.Add(midnight.AddDays(-i).ToUniversalTime());
        }
        else
        {
            bool block = intent.Command == CustomCommandType.GetBlockLoadProfile;
            bool instant = intent.Command == CustomCommandType.GetStoredInstantaneousProfile;
            int step = block || instant ? 15 * 60 : 60 * 60;
            int count = block ? 7 * 96 : instant ? 96 : 32;
            long end = now.ToUnixTimeSeconds() / step * step;
            for (int i = count - 1; i >= 0; i--) times.Add(DateTimeOffset.FromUnixTimeSeconds(end - i * (long)step));
        }
        var (start, selectedCount) = CustomProfileCommand.SelectEntries((uint)times.Count, intent.Selector, intent.ValueFrom, intent.ValueTo);
        var selected = times.Skip(checked((int)start - 1)).Take(checked((int)selectedCount)).ToList();
        if (selected.Count > options.MaxProfileRows) throw new InvalidOperationException("Custom profile row limit exceeded; narrow the range.");
        return selected;
    }

    private static IReadOnlyList<DateTimeOffset> GenerateDateRange(CommandIntent intent, DateTimeOffset now, CustomPullOptions options)
    {
        if (intent.ValueFrom > intent.ValueTo) throw new ArgumentException("Date range is reversed.");
        int offset = intent.Command == CustomCommandType.GetBlockLoadProfile ? options.BlockRequestOffsetMinutes : 0;
        var from = DateTimeOffset.FromUnixTimeSeconds(intent.ValueFrom).AddMinutes(-offset);
        var to = DateTimeOffset.FromUnixTimeSeconds(intent.ValueTo).AddMinutes(-offset);
        if (to > now) to = now;
        var local = from.ToOffset(TimeSpan.FromMinutes(options.ResponseTimestampOffsetMinutes));
        bool billing = intent.Command == CustomCommandType.GetBillingProfile;
        bool daily = intent.Command == CustomCommandType.GetDailyLoadProfile;
        int seconds = intent.Command is CustomCommandType.GetBlockLoadProfile or CustomCommandType.GetStoredInstantaneousProfile ? 900 : 3600;
        DateTimeOffset cursor = billing
            ? new(local.Year, local.Month, 1, 0, 0, 0, local.Offset)
            : daily ? new(local.Year, local.Month, local.Day, 0, 0, 0, local.Offset)
            : DateTimeOffset.FromUnixTimeSeconds(from.ToUnixTimeSeconds() / seconds * seconds);
        DateTimeOffset Next(DateTimeOffset time) => billing ? time.AddMonths(1) : daily ? time.AddDays(1) : time.AddSeconds(seconds);
        if (cursor < from) cursor = Next(cursor);
        var result = new List<DateTimeOffset>();
        for (; cursor <= to; cursor = Next(cursor))
        {
            if (result.Count >= options.MaxProfileRows) throw new InvalidOperationException("Custom profile row limit exceeded; narrow the date range.");
            result.Add(cursor.ToUniversalTime());
        }
        return result;
    }

    public static object Value(TemplateField field, long meter, DateTimeOffset timestamp, string kind, int eventId, int blockPeriodMinutes = 15)
    {
        if (field.DataType == "DateTime") return new GXDateTime(timestamp.UtcDateTime);
        string name = field.ParameterName.ToLowerInvariant();
        decimal phaseCurrent = 2m + meter % 20 / 10m;
        decimal voltage = 230m + meter % 10;
        decimal kw = voltage * phaseCurrent * 0.98m / 1000m;
        decimal days = (decimal)(timestamp - new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalDays;
        decimal cumulative = 1000m + meter % 5000 + Math.Max(0m, days) * 8m;
        decimal value;
        if (name == "eventid") value = eventId;
        else if (name.Contains("voltage")) value = voltage;
        else if (name.Contains("current") && !name.Contains("balance")) value = phaseCurrent;
        else if (name.Contains("frequency")) value = 50m;
        else if (name.Contains("powerfactor") || name.Contains("averagepf")) value = 0.98m;
        else if (name.StartsWith("maxdemand") || name is "mdw" or "mdva" || name.StartsWith("maximumdemand")) value = kw * 1.2m;
        else if (name.Contains("energy") || name.Contains("kvarh") || name is "netkwh" or "netkvah")
        {
            value = kind == "BLOCK" ? 8m * blockPeriodMinutes / (24m * 60m) : cumulative;
            if (name.Contains("export")) value *= 0.05m;
            if (name.Contains("kvah")) value /= 0.98m;
            if (name.Contains("tz")) value /= 6m;
        }
        else if (name.Contains("apparentpower")) value = kw / 0.98m;
        else if (name.Contains("activepower")) value = kw;
        else if (name.Contains("reactivepower")) value = kw * 0.2m;
        else if (name.Contains("poweronduration")) value = kind == "BILL" ? 30 * 24 * 60 : 24 * 60;
        else if (name.Contains("count") || name.Contains("sequencenumber")) value = 12;
        else if (name.Contains("loadlimitvalue")) value = 10;
        else if (name.Contains("status")) value = 1;
        else
        {
            // A model-only field with no electrical semantic receives a stable small raw value.
            // Its presence/type/order still comes exclusively from the selected HES layout.
            value = (1 + (meter + field.SerialNumber) % 7) * (decimal)Math.Pow(10, field.Scalar);
        }
        return value;
    }
}
