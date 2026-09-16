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
    Task<IBatchTrafficSession> OpenAsync(MeterBatch batch, BatchTrafficKind kind, CancellationToken token);
}

public sealed record BatchTrafficState(string Status, long Sent = 0, long Failed = 0, long Skipped = 0,
    DateTimeOffset? NextWindow = null, string? Error = null);

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

    public BatchTrafficState State(MeterBatch batch, BatchTrafficKind kind) =>
        !batch.Traffic.Enabled(kind) ? new("Stopped") : batch.Status != BatchStatus.Running
            ? new("Waiting for batch") : _states.GetValueOrDefault((batch.Id, kind), new("Starting"));

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
                var window = BatchTrafficSchedule.Window(_clock.GetUtcNow(), job.Kind, _zone);
                _states[key] = new("Scheduled", NextWindow: window.Start);
                Changed?.Invoke();
                if (window.Start > _clock.GetUtcNow()) await Task.Delay(window.Start - _clock.GetUtcNow(), _clock, token);
                long sent = 0, failed = 0, skipped = 0, cursor = 0;
                using var deadline = new CancellationTokenSource(TimeSpan.FromTicks(Math.Max(1, (window.End - _clock.GetUtcNow()).Ticks)), _clock);
                using var windowStop = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
                while (_clock.GetUtcNow() < window.End)
                {
                    try
                    {
                        await using var session = await _sender.OpenAsync(job.Batch, job.Kind, windowStop.Token);
                        _states[key] = new("Sending", sent, failed, skipped, window.Start);
                        Changed?.Invoke();
                        await Parallel.ForEachAsync(DueMeters(windowStop.Token), new ParallelOptions
                        { MaxDegreeOfParallelism = _concurrency, CancellationToken = windowStop.Token }, async (index, ct) =>
                        {
                            ct.ThrowIfCancellationRequested();
                            if (!Eligible(job) || _clock.GetUtcNow() >= window.End) return;
                            await session.SendAsync(index, ct);
                            Interlocked.Increment(ref sent);
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
                _states[key] = new("Waiting for next window", sent, failed, skipped, window.End);
                Changed?.Invoke();
                if (window.End > _clock.GetUtcNow()) await Task.Delay(window.End - _clock.GetUtcNow(), _clock, token);

                async IAsyncEnumerable<long> DueMeters([EnumeratorCancellation] CancellationToken ct)
                {
                    while (cursor < job.Batch.Count && _clock.GetUtcNow() < window.End)
                    {
                        ct.ThrowIfCancellationRequested();
                        int second = (int)Math.Max(0, (_clock.GetUtcNow() - window.Start).TotalSeconds);
                        long first = BatchTrafficSchedule.FirstMeter(job.Batch.Count, second);
                        skipped += Math.Max(0, first - cursor);
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
