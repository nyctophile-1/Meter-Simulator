using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Brain;

public interface IBatchTrafficSession : IAsyncDisposable
{
    Task SendAsync(long meterIndex, CancellationToken token);
}

public interface IBatchTrafficSender
{
    int BlockCapturePeriodSeconds(MeterBatch batch);
    Task<IBatchTrafficSession> OpenAsync(MeterBatch batch, BatchTrafficKind kind, DateTimeOffset? captureSlot, CancellationToken token);
}

public sealed record BatchTrafficState(string Status, long Sent = 0, long Failed = 0, long Skipped = 0,
    DateTimeOffset? NextWindow = null, string? Error = null,
    BlockLoadWindowReport? LastBlockLoadWindow = null);

public sealed class BlockLoadWindowReport(DateTimeOffset slot, long startIndex, long expected, long sent, long[] completedWords)
{
    public DateTimeOffset Slot { get; } = slot;
    public long Expected { get; } = expected;
    public long Sent { get; } = sent;
    public long Unsent => Expected - Sent;

    public IEnumerable<long> UnsentMeterIndexes()
    {
        for (long offset = 0; offset < Expected; offset++)
            if ((completedWords[offset / 64] & (1L << (int)(offset % 64))) == 0)
                yield return startIndex + offset;
    }
}

public sealed class BatchTrafficService : BackgroundService
{
    private readonly MeterRegistry _registry;
    private readonly IBatchTrafficSender _sender;
    private readonly TimeProvider _clock;
    private readonly TimeZoneInfo _zone;
    private readonly int _concurrency;
    private readonly ILogger<BatchTrafficService> _logger;
    private readonly ConcurrentDictionary<(int, BatchTrafficKind), Job> _jobs = new();
    private readonly ConcurrentDictionary<(int, BatchTrafficKind), BatchTrafficState> _states = new();
    private readonly ConcurrentDictionary<int, BlockLoadWindowReport> _lastBlockLoadWindows = new();
    public event Action? Changed;
    public string TimeZoneId => _zone.Id;

    public BatchTrafficService(MeterRegistry registry, IBatchTrafficSender sender, TimeProvider clock,
        IOptions<BatchTrafficOptions> options, ILogger<BatchTrafficService> logger)
    {
        _registry = registry;
        _sender = sender;
        _clock = clock;
        _zone = TimeZoneInfo.FindSystemTimeZoneById(options.Value.TimeZoneId);
        _concurrency = Math.Clamp(options.Value.MaxConcurrency, 1, 1024);
        _logger = logger;
    }

    public BatchTrafficState State(MeterBatch batch, BatchTrafficKind kind)
    {
        BatchTrafficState state = !batch.Traffic.Enabled(kind) ? new("Stopped") : batch.Status != BatchStatus.Running
            ? new("Waiting for batch") : _states.GetValueOrDefault((batch.Id, kind), new("Starting"));
        return kind == BatchTrafficKind.BlockLoad && _lastBlockLoadWindows.TryGetValue(batch.Id, out var report)
            ? state with { LastBlockLoadWindow = report } : state;
    }

    private bool Eligible(Job job) => job.Batch.Status == BatchStatus.Running
        && job.Batch.Traffic.Enabled(job.Kind)
        && ReferenceEquals(_registry.GetBatchForIndex(job.Batch.StartIndex), job.Batch);

    private void OnRegistryChanged()
    {
        foreach (var job in _jobs.Values)
            if (!Eligible(job)) job.Cancel();
        Changed?.Invoke();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _registry.Changed += OnRegistryChanged;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                foreach (var (key, job) in _jobs.ToArray())
                {
                    if (!Eligible(job)) job.Cancel();
                    if (!job.Work.IsCompleted) continue;
                    await job.Work;
                    _jobs.TryRemove(key, out _);
                    job.Stop.Dispose();
                }
                foreach (var batch in _registry.Batches.Where(b => b.Status == BatchStatus.Running))
                    foreach (var kind in Enum.GetValues<BatchTrafficKind>())
                    {
                        var key = (batch.Id, kind);
                        if (!batch.Traffic.Enabled(kind) || _jobs.ContainsKey(key)) continue;
                        var job = new Job(batch, kind, CancellationTokenSource.CreateLinkedTokenSource(stoppingToken));
                        _jobs[key] = job;
                        job.Work = RunAsync(job);
                    }
                foreach (var key in _states.Keys)
                    if (!_registry.Batches.Any(b => b.Id == key.Item1)) _states.TryRemove(key, out _);
                foreach (int batchId in _lastBlockLoadWindows.Keys)
                    if (!_registry.Batches.Any(b => b.Id == batchId)) _lastBlockLoadWindows.TryRemove(batchId, out _);
                Changed?.Invoke();
                await Task.Delay(TimeSpan.FromSeconds(1), _clock, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            _registry.Changed -= OnRegistryChanged;
            foreach (var job in _jobs.Values) job.Stop.Cancel();
            await Task.WhenAll(_jobs.Values.Select(j => j.Work));
            foreach (var job in _jobs.Values) job.Stop.Dispose();
            _jobs.Clear();
        }
    }

    private async Task RunAsync(Job job)
    {
        var key = (job.Batch.Id, job.Kind);
        var token = job.Stop.Token;
        try
        {
            while (true)
            {
                token.ThrowIfCancellationRequested();
                int blockPeriod;
                BatchTrafficWindow window;
                try
                {
                    blockPeriod = job.Kind == BatchTrafficKind.BlockLoad
                        ? _sender.BlockCapturePeriodSeconds(job.Batch) : BatchTrafficSchedule.WindowSeconds;
                    window = BatchTrafficSchedule.Window(_clock.GetUtcNow(), job.Kind, _zone, blockPeriod);
                }
                catch (Exception ex)
                {
                    _states[key] = new("Waiting for valid profile", Error: ex.Message);
                    _logger.LogWarning(ex, "Batch {BatchId} Block Load has no valid capture period", job.Batch.Id);
                    await Task.Delay(TimeSpan.FromSeconds(30), _clock, token);
                    continue;
                }
                _states[key] = new("Scheduled", NextWindow: window.Start);
                Changed?.Invoke();
                if (window.Start > _clock.GetUtcNow()) await Task.Delay(window.Start - _clock.GetUtcNow(), _clock, token);
                if (_clock.GetUtcNow() >= window.End) continue;
                long sent = 0, failed = 0, skipped = 0, cursor = 0;
                string? firstError = null;
                long[]? completedWords = job.Kind == BatchTrafficKind.BlockLoad
                    ? new long[checked((int)((job.Batch.Count + 63) / 64))] : null;
                using var deadline = new CancellationTokenSource(TimeSpan.FromTicks(Math.Max(1, (window.End - _clock.GetUtcNow()).Ticks)), _clock);
                using var windowStop = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
                while (_clock.GetUtcNow() < window.End)
                {
                    try
                    {
                        await using var session = await _sender.OpenAsync(job.Batch, job.Kind,
                            job.Kind == BatchTrafficKind.BlockLoad ? window.Start : null, windowStop.Token);
                        _states[key] = new("Sending", sent, failed, skipped, window.Start);
                        Changed?.Invoke();
                        await Parallel.ForEachAsync(DueMeters(windowStop.Token), new ParallelOptions
                        { MaxDegreeOfParallelism = _concurrency, CancellationToken = windowStop.Token }, async (index, ct) =>
                        {
                            ct.ThrowIfCancellationRequested();
                            if (!Eligible(job) || _clock.GetUtcNow() >= window.End) return;
                            try
                            {
                                await session.SendAsync(index, ct);
                                if (completedWords is not null)
                                {
                                    long offset = index - job.Batch.StartIndex;
                                    Interlocked.Or(ref completedWords[checked((int)(offset / 64))], 1L << (int)(offset % 64));
                                }
                                Interlocked.Increment(ref sent);
                            }
                            catch (PushSkippedException) { Interlocked.Increment(ref skipped); }
                            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                            catch (Exception ex) when (job.Kind != BatchTrafficKind.Routing && ex is not BatchTrafficSourceChangedException)
                            {
                                Interlocked.Increment(ref failed);
                                Interlocked.CompareExchange(ref firstError, ex.Message, null);
                            }
                        });
                        break;
                    }
                    catch (OperationCanceledException) when (windowStop.IsCancellationRequested) { break; }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref failed);
                        _states[key] = new("Retrying", sent, failed, skipped, window.Start, ex.Message);
                        _logger.LogWarning("Batch {BatchId} {Kind}: {Error}", job.Batch.Id, job.Kind, ex.Message);
                        Changed?.Invoke();
                        try { await Task.Delay(TimeSpan.FromSeconds(30), _clock, windowStop.Token); }
                        catch (OperationCanceledException) when (windowStop.IsCancellationRequested) { break; }
                    }
                }
                if (job.Kind == BatchTrafficKind.BlockLoad && !token.IsCancellationRequested)
                {
                    long completed = Interlocked.Read(ref sent);
                    var report = new BlockLoadWindowReport(window.Start, job.Batch.StartIndex, job.Batch.Count,
                        completed, completedWords!);
                    _lastBlockLoadWindows[job.Batch.Id] = report;
                    if (report.Unsent > 0)
                        _logger.LogWarning("Batch {BatchId} Block Load slot {Slot}: {Sent}/{Expected} meter pushes completed; {Unsent} unsent at capture boundary",
                            job.Batch.Id, report.Slot, report.Sent, report.Expected, report.Unsent);
                    else
                        _logger.LogInformation("Batch {BatchId} Block Load slot {Slot}: all {Expected} meter pushes completed",
                            job.Batch.Id, report.Slot, report.Expected);
                }
                if (failed > 0 && job.Kind is not (BatchTrafficKind.BlockLoad or BatchTrafficKind.Routing))
                    _logger.LogWarning("Batch {BatchId} {Kind} window {Slot}: {Failed} meter pushes failed; first error: {Error}",
                        job.Batch.Id, job.Kind, window.Start, failed, firstError);
                _states[key] = new("Waiting for next window", sent, failed, skipped, window.End, firstError);
                Changed?.Invoke();
                if (window.End > _clock.GetUtcNow()) await Task.Delay(window.End - _clock.GetUtcNow(), _clock, token);

                async IAsyncEnumerable<long> DueMeters([EnumeratorCancellation] CancellationToken ct)
                {
                    if (job.Kind != BatchTrafficKind.Routing)
                    {
                        while (cursor < job.Batch.Count && _clock.GetUtcNow() < window.End)
                        {
                            ct.ThrowIfCancellationRequested();
                            yield return job.Batch.StartIndex + cursor++;
                        }
                        yield break;
                    }
                    while (cursor < job.Batch.Count && _clock.GetUtcNow() < window.End)
                    {
                        ct.ThrowIfCancellationRequested();
                        int second = (int)Math.Max(0, (_clock.GetUtcNow() - window.Start).TotalSeconds);
                        long first = BatchTrafficSchedule.FirstMeter(job.Batch.Count, second);
                        Interlocked.Add(ref skipped, Math.Max(0, first - cursor));
                        cursor = Math.Max(cursor, first);
                        long end = BatchTrafficSchedule.FirstMeter(job.Batch.Count, second + 1);
                        while (cursor < end) yield return job.Batch.StartIndex + cursor++;
                        _states[key] = new("Sending", Interlocked.Read(ref sent), Interlocked.Read(ref failed), skipped, window.Start);
                        var next = window.Start.AddSeconds(second + 1);
                        if (next > _clock.GetUtcNow()) await Task.Delay(next - _clock.GetUtcNow(), _clock, ct);
                    }
                }
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }

    private sealed class Job(MeterBatch batch, BatchTrafficKind kind, CancellationTokenSource stop)
    {
        public MeterBatch Batch { get; } = batch;
        public BatchTrafficKind Kind { get; } = kind;
        public CancellationTokenSource Stop { get; } = stop;
        public Task Work { get; set; } = Task.CompletedTask;
        public void Cancel()
        {
            try { Stop.Cancel(); }
            catch (ObjectDisposedException) { }
        }
    }
}
