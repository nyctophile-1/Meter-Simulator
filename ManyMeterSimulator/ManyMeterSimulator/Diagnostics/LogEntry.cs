using Serilog.Events;

namespace ManyMeterSimulator.Diagnostics;

/// <summary>One rendered log line, as the live-logs UI consumes it.</summary>
public sealed record LogEntry(
    DateTimeOffset Timestamp,
    LogEventLevel Level,
    string Source,
    string Message,
    string? Exception);
