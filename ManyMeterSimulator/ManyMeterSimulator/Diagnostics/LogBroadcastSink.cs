using Serilog.Core;
using Serilog.Events;

namespace ManyMeterSimulator.Diagnostics;

/// <summary>
/// Serilog sink that feeds every event into the <see cref="LogBroadcaster"/> for the live-logs UI.
/// Runs alongside the console and file sinks, so the UI sees the full Information (or Debug, when the
/// level switch is raised) stream even though the file keeps only Warning+.
/// </summary>
public sealed class LogBroadcastSink : ILogEventSink
{
    private readonly LogBroadcaster _broadcaster;

    public LogBroadcastSink(LogBroadcaster broadcaster) => _broadcaster = broadcaster;

    public void Emit(LogEvent logEvent)
    {
        string source = string.Empty;
        if (logEvent.Properties.TryGetValue("SourceContext", out LogEventPropertyValue? sc)
            && sc is ScalarValue { Value: string full })
        {
            int dot = full.LastIndexOf('.');
            source = dot >= 0 ? full[(dot + 1)..] : full;
        }

        _broadcaster.Publish(new LogEntry(
            logEvent.Timestamp,
            logEvent.Level,
            source,
            logEvent.RenderMessage(),
            logEvent.Exception?.ToString()));
    }
}
