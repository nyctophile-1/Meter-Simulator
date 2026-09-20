namespace ManyMeterSimulator.Brain;

public sealed record HistoricalPushPosition(int BatchId, string BatchName, string Profile, DateTimeOffset ReadingTime)
{
    public string ProfileName => HistoricalProfileProgress.NameOf(Profile);
}

public sealed record HistoricalSlotProgress(HistoricalPushPosition Position, long Total, long Sent,
    long Skipped, long Failed, int InFlight)
{
    public long Processed => Sent + Skipped + Failed;
}

public sealed record HistoricalProfileProgress(int BatchId, string BatchName, string Profile, long Total,
    long Sent, long Skipped, long Failed, long MessagesSent, long MessagesFailed,
    DateTimeOffset? FirstSentReading, DateTimeOffset? LastSentReading)
{
    public string ProfileName => NameOf(Profile);

    internal static string NameOf(string profile) => profile switch
    {
        "0.0.25.9.0.255" => "Instantaneous",
        "0.5.25.9.0.255" => "Block load",
        _ => profile
    };
}

internal sealed class HistoricalPushTelemetry
{
    private readonly object _sync = new();
    private readonly DateTimeOffset _from;
    private readonly DateTimeOffset _to;

    private sealed class Counters(HistoricalPushSource source, long total)
    {
        public string BatchName { get; } = source.BatchName ?? $"Batch {source.BatchId}";
        public long Sent, Skipped, Failed, Messages, Rejected;
        public DateTimeOffset? FirstReading, LastReading;

        public HistoricalProfileProgress Snapshot() => new(source.BatchId, BatchName, source.Profile, total,
            Sent, Skipped, Failed, Messages, Rejected, FirstReading, LastReading);
    }

    private readonly Dictionary<HistoricalPushSource, Counters> _profiles;
    private readonly Queue<(TimeSpan Time, long Records, long Messages)> _samples = new();

    private sealed class Slot(HistoricalPushPosition position, long total)
    {
        public HistoricalPushPosition Position { get; } = position;
        public long Sent, Skipped, Failed;
        public int InFlight;
        public HistoricalSlotProgress Snapshot() => new(Position, total, Sent, Skipped, Failed, InFlight);
    }

    private readonly Dictionary<HistoricalPushSource, Slot> _slots = new();
    private DateTimeOffset? _readingTime;
    private HistoricalPushPosition? _lastSuccessful;
    private long _sent, _skipped, _failed, _messages, _rejected;
    private string? _error;

    public HistoricalPushTelemetry(HistoricalPushSource[] sources, DateTimeOffset from, DateTimeOffset to,
        HistoricalPushProgress? resume = null)
    {
        _from = from;
        _to = to;
        _profiles = sources.ToDictionary(source => source, source => new Counters(source,
            checked(HistoricalPushRun.SlotCount(from, to, source.PeriodSeconds) * source.Count)));
        if (resume is not null)
        {
            foreach (var source in sources)
            {
                var saved = resume.Profiles.Single(p => p.BatchId == source.BatchId && p.Profile == source.Profile);
                var profile = _profiles[source];
                profile.Sent = saved.Sent;
                profile.Skipped = saved.Skipped;
                profile.Failed = saved.Failed;
                profile.Messages = saved.MessagesSent;
                profile.Rejected = saved.MessagesFailed;
                profile.FirstReading = saved.FirstSentReading;
                profile.LastReading = saved.LastSentReading;
                var slot = resume.CurrentSlots.SingleOrDefault(p => p.Position.BatchId == source.BatchId && p.Position.Profile == source.Profile);
                if (slot is not null)
                {
                    _slots[source] = new(slot.Position, slot.Total) { Sent = slot.Sent, Skipped = slot.Skipped, Failed = slot.Failed };
                }
            }

            _sent = resume.Sent;
            _skipped = resume.Skipped;
            _failed = resume.Failed;
            _messages = resume.MessagesSent;
            _rejected = resume.MessagesFailed;
            _lastSuccessful = resume.LastSuccessfulPush;
            _readingTime = resume.ReadingTime;
            _error = resume.Error;
        }

        _samples.Enqueue((resume?.Elapsed ?? TimeSpan.Zero, _sent, _messages));
    }

    public void BeginSlot(HistoricalPushSource source, DateTimeOffset time) => BeginSlots([source], time);

    public void BeginSlots(HistoricalPushSource[] sources, DateTimeOffset time)
    {
        lock (_sync)
        {
            if (_readingTime != time)
            {
                _slots.Clear();
                _readingTime = time;
            }

            foreach (var source in sources)
            {
                _slots.TryAdd(source, new(new(source.BatchId, _profiles[source].BatchName, source.Profile, time), source.Count));
            }
        }
    }

    public void Sending(HistoricalPushSource source, int delta)
    {
        lock (_sync)
        {
            _slots[source].InFlight += delta;
        }
    }

    public void Record(HistoricalPushSource source, DateTimeOffset time, long sent = 0, long skipped = 0,
        long failed = 0, long messages = 0, long rejected = 0, string? error = null)
    {
        lock (_sync)
        {
            _sent += sent;
            _skipped += skipped;
            _failed += failed;
            _messages += messages;
            _rejected += rejected;
            _error ??= error;

            var profile = _profiles[source];
            profile.Sent += sent;
            profile.Skipped += skipped;
            profile.Failed += failed;
            profile.Messages += messages;
            profile.Rejected += rejected;
            var slot = _slots[source];
            slot.Sent += sent;
            slot.Skipped += skipped;
            slot.Failed += failed;

            if (sent > 0)
            {
                profile.FirstReading ??= time;
                profile.LastReading = time;
                _lastSuccessful = slot.Position;
            }
        }
    }

    public HistoricalPushProgress Snapshot(TimeSpan elapsed, bool finished = false)
    {
        lock (_sync)
        {
            // Retain one sample at the start of the measured window.
            while (_samples.Count > 1 && _samples.ElementAt(1).Time <= elapsed - TimeSpan.FromSeconds(5))
            {
                _samples.Dequeue();
            }

            var baseline = _samples.Peek();
            double seconds = (elapsed - baseline.Time).TotalSeconds;
            if (elapsed > _samples.Last().Time)
            {
                _samples.Enqueue((elapsed, _sent, _messages));
            }

            var profiles = _profiles.Values.Select(p => p.Snapshot()).ToArray();
            var slots = finished ? [] : _slots.Values.Select(s => s.Snapshot()).ToArray();
            return new(_from, _to, profiles.Sum(p => p.Total), _sent, _skipped, _failed, _messages,
                _rejected, elapsed, _readingTime, _error)
            {
                CurrentSlot = slots.Length == 1 ? slots[0] : null,
                CurrentSlots = slots,
                LastSuccessfulPush = _lastSuccessful,
                Profiles = profiles,
                CurrentRecordsPerSecond = !finished && seconds > 0 ? (_sent - baseline.Records) / seconds : 0,
                CurrentMessagesPerSecond = !finished && seconds > 0 ? (_messages - baseline.Messages) / seconds : 0,
                RateWindowSeconds = seconds
            };
        }
    }
}
