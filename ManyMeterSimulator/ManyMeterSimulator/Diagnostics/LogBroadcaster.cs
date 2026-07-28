namespace ManyMeterSimulator.Diagnostics;

/// <summary>
/// In-memory, bounded ring of the most recent log lines plus a fan-out event for new ones. This is
/// what the live-logs UI reads instead of tailing the file — bounded, so memory stays flat no matter
/// how long the process runs or how chatty a load test gets. Not durable by design.
/// </summary>
public sealed class LogBroadcaster
{
    private readonly int _capacity;
    private readonly Queue<LogEntry> _buffer;
    private readonly object _lock = new();

    /// <summary>Raised for every published line. Handlers run on the publishing thread — keep them cheap.</summary>
    public event Action<LogEntry>? OnLog;

    public LogBroadcaster(int capacity = 1000)
    {
        _capacity = capacity;
        _buffer = new Queue<LogEntry>(capacity + 1);
    }

    public void Publish(LogEntry entry)
    {
        lock (_lock)
        {
            _buffer.Enqueue(entry);
            while (_buffer.Count > _capacity)
            {
                _buffer.Dequeue();
            }
        }

        OnLog?.Invoke(entry);
    }

    /// <summary>Point-in-time copy of the buffer (oldest first), for seeding a newly-opened view.</summary>
    public IReadOnlyList<LogEntry> Snapshot()
    {
        lock (_lock)
        {
            return _buffer.ToArray();
        }
    }
}
