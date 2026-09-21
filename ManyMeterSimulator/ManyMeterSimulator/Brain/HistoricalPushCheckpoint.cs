using System.Text.Json;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Brain;

public sealed record HistoricalSourceCheckpoint(string Identity, long NextRecord, long[] CompletedAhead);

public sealed record HistoricalPushCheckpoint(int Version, HistoricalPushRequest Request,
    HistoricalPushProgress Progress, HistoricalSourceCheckpoint[] Sources, DateTimeOffset SavedAtUtc)
{
    public bool HasRemaining => Progress.Processed < Progress.Total;
}

public interface IHistoricalPushCheckpointStore
{
    HistoricalPushCheckpoint? Load();
    void Save(HistoricalPushCheckpoint checkpoint);
}

public sealed class JsonHistoricalPushCheckpointStore : IHistoricalPushCheckpointStore
{
    private readonly string _path;

    public JsonHistoricalPushCheckpointStore(IOptions<PersistenceOptions> options, IHostEnvironment environment)
        : this(Path.GetFullPath(Path.Combine(environment.ContentRootPath, options.Value.Folder, "historical-push.json")))
    {
    }

    public JsonHistoricalPushCheckpointStore(string path)
    {
        _path = path;
    }

    public HistoricalPushCheckpoint? Load()
    {
        if (!File.Exists(_path))
        {
            return null;
        }

        return JsonSerializer.Deserialize<HistoricalPushCheckpoint>(File.ReadAllText(_path))
            ?? throw new InvalidOperationException("The saved historical run is empty.");
    }

    public void Save(HistoricalPushCheckpoint checkpoint)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(checkpoint);

        using (var stream = new FileStream(_path + ".tmp", FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }

        File.Move(_path + ".tmp", _path, overwrite: true);
    }
}

internal sealed class HistoricalPushCursor(HistoricalPushSource source, DateTimeOffset from,
    DateTimeOffset to, HistoricalSourceCheckpoint? saved)
{
    private readonly object _sync = new();
    private readonly HashSet<long> _completed = saved?.CompletedAhead.ToHashSet() ?? [];
    private long _next = saved?.NextRecord ?? 0;
    public HistoricalPushSource Source { get; } = source;
    public long Total { get; } = checked(HistoricalPushRun.SlotCount(from, to, source.PeriodSeconds) * source.Count);
    public long Next => _next;
    public DateTimeOffset Time(long ordinal) => HistoricalPushRun.FirstSlot(from, source.PeriodSeconds)
        .AddSeconds(checked(ordinal / source.Count * source.PeriodSeconds));

    public long Unfinished(long ordinal)
    {
        while (_completed.Contains(ordinal))
        {
            ordinal++;
        }

        return ordinal;
    }

    public void Complete(long ordinal)
    {
        lock (_sync)
        {
            if (ordinal < _next)
            {
                return;
            }

            _completed.Add(ordinal);
            while (_completed.Remove(_next))
            {
                _next++;
            }
        }
    }

    public void Validate()
    {
        if (_next < 0 || _next > Total ||
            (saved is not null && saved.CompletedAhead.Length != _completed.Count) ||
            _completed.Any(value => value <= _next || value >= Total))
        {
            throw new InvalidOperationException("The saved historical meter position is invalid.");
        }
    }

    public HistoricalSourceCheckpoint Snapshot() => new(Source.Identity, _next, _completed.Order().ToArray());
}
