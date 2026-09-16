namespace MeterSimulator.Models;

public static class EventStatusWord
{
    public const string LogicalName = "0.0.94.91.18.255";
    public const string PushLogicalName = "0.4.25.9.0.255";

    public static void Validate(string? value)
    {
        if (value is null || value.Length != 128 || value.Any(bit => bit is not ('0' or '1')))
            throw new ArgumentException("ESW must contain exactly 128 binary digits.", nameof(value));
    }
}
