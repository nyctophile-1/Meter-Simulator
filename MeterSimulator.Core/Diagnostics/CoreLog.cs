using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MeterSimulator.Diagnostics;

/// <summary>
/// Lightweight logging shim for the Core library. Core is full of <c>static</c> helper methods and
/// had 100+ legacy <c>Console.WriteLine</c> call sites, which makes per-instance / constructor-injected
/// loggers impractical here. The host configures this once at startup with a real <see cref="ILogger"/>;
/// until then it is a silent no-op (so tests and standalone use don't spew to the console).
///
/// Everything Core logs therefore flows through the host's normal ILogger/Serilog pipeline — the same
/// console/file sinks and the live-logs UI — instead of bypassing it via the console.
///
/// Levels: <see cref="Debug"/> for chatty per-build / per-read diagnostics (off by default — the file
/// keeps only Warning+), <see cref="Warn"/> and <see cref="Error"/> for things worth surfacing.
/// Messages are already fully formatted, so they are passed as a single value (not a template hole)
/// to avoid the runtime trying to parse any '{' in the text.
/// </summary>
public static class CoreLog
{
    private static ILogger _logger = NullLogger.Instance;

    public static void Configure(ILogger logger) => _logger = logger ?? NullLogger.Instance;

    public static void Debug(string message) => _logger.LogDebug("{Message}", message);

    public static void Warn(string message) => _logger.LogWarning("{Message}", message);

    public static void Error(string message) => _logger.LogError("{Message}", message);
}
