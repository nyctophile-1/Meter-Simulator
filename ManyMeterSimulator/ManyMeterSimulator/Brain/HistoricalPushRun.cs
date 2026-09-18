using System.Diagnostics;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Brain;

public sealed record HistoricalPushRequest
{
    public IReadOnlyList<int> BatchIds { get; init; } = [];
    public int Days { get; init; } = 7;
    public int InstantaneousIntervalMinutes { get; init; } = 30;
    public int MaxConcurrency { get; init; } = 64;
    public int RecordsPerSecond { get; init; } = 1000;
    public int PublisherCount { get; init; } = 8;
    public int Qos { get; init; } = 1;

    public void Validate()
    {
        if (BatchIds.Count == 0 || BatchIds.Distinct().Count() != BatchIds.Count)
            throw new ArgumentException("Select at least one batch, without duplicates.");
        if (Days is < 1 or > 3650) throw new ArgumentException("Days must be 1 to 3650.");
        if (InstantaneousIntervalMinutes is < 1 or > 1440) throw new ArgumentException("Instantaneous interval must be 1 to 1440 minutes.");
        if (MaxConcurrency is < 1 or > 1024) throw new ArgumentException("Concurrency must be 1 to 1024.");
        if (PublisherCount is < 1 or > 256 || PublisherCount > MaxConcurrency)
            throw new ArgumentException("Publishers must be 1 to 256 and no more than concurrency.");
        if (Qos is < 0 or > 2) throw new ArgumentException("QoS must be 0, 1 or 2.");
        MqttPublishRateLimiter.Validate(RecordsPerSecond);
    }
}

public sealed record HistoricalPushProgress(DateTimeOffset From, DateTimeOffset To, long Total,
    long Sent = 0, long Skipped = 0, long Failed = 0, long MessagesSent = 0, long MessagesFailed = 0,
    TimeSpan Elapsed = default, DateTimeOffset? ReadingTime = null, string? Error = null)
{
    public long Processed => Sent + Skipped + Failed;
    public double RecordsPerSecond => Elapsed.TotalSeconds > 0 ? Sent / Elapsed.TotalSeconds : 0;
}

internal sealed record HistoricalPushSource(int BatchId, long StartIndex, long Count, NicType Nic,
    string Profile, int PeriodSeconds, Func<bool> IsCurrent,
    Func<MeterRef, DateTimeOffset, CancellationToken, Task<PushDeliveryResult>> Send);

public sealed partial class PushCoordinator
{
    internal async Task<HistoricalPushRun> OpenHistoricalRunAsync(HistoricalPushRequest request, CancellationToken token)
    {
        request = request with { BatchIds = request.BatchIds.ToArray() };
        request.Validate();
        var end = _clock.GetUtcNow();
        var start = end.AddDays(-request.Days);
        var pools = new Dictionary<BrokerBinding, IMqttPushPool>();
        var sources = new List<HistoricalPushSource>();
        foreach (int id in request.BatchIds)
        {
            token.ThrowIfCancellationRequested();
            var batch = _registry.Batches.SingleOrDefault(b => b.Id == id)
                ?? throw new InvalidOperationException($"Batch {id} no longer exists.");
            if (batch.Status != BatchStatus.Running) throw new InvalidOperationException($"Start batch '{batch.Name}' first.");
            int blockSeconds;
            if (batch.NicType == NicType.MqttWirepas)
                blockSeconds = checked(_customPullOptions.GetBlockPeriodMinutes(batch.HesTemplateId
                    ?? throw new InvalidOperationException("Missing HES template.")) * 60);
            else
            {
                var session = _sessions.GetOrCreate(new MeterRef(batch.StartIndex, batch.NicType));
                lock (session) blockSeconds = session.BlockPushPeriodSeconds;
            }
            foreach (var (profile, seconds) in new[] { ("0.0.25.9.0.255", request.InstantaneousIntervalMinutes * 60), ("0.5.25.9.0.255", blockSeconds) })
            {
                if (batch.NicType == NicType.Tcp4G)
                {
                    var source = ResolveTcpSource(id, new TcpPushRequest { BatchIds = [id], PushSetupLogicalName = profile }, _options.UseCiphering);
                    sources.Add(new(id, batch.StartIndex, batch.Count, batch.NicType, profile, seconds, source.IsCurrent,
                        (meter, time, ct) => source.Send(meter, source.BuildAt!(meter, time), ct)));
                }
                else
                {
                    var source = ResolveMqttSource(id, new MqttPushRequest { BatchIds = [id], PushSetupLogicalName = profile });
                    pools.TryAdd(source.Binding, null!);
                    sources.Add(new(id, batch.StartIndex, batch.Count, batch.NicType, profile, seconds, source.IsCurrent,
                        async (meter, time, ct) =>
                        {
                            var result = await pools[source.Binding].PublishMeterAsync(source.BuildAt!(meter, time), ct);
                            return new(result.Sent, result.Failed, result.Error);
                        }));
                }
            }
        }
        try
        {
            foreach (var binding in pools.Keys.ToArray())
                pools[binding] = await _mqtt.OpenPoolAsync(binding, request.PublisherCount, request.Qos, _options.PublishTimeoutSeconds, token);
            token.ThrowIfCancellationRequested();
            return new HistoricalPushRun(sources.ToArray(), pools.Values.ToArray(), request, start, end, AllowPushAsync, _metrics);
        }
        catch
        {
            foreach (var pool in pools.Values.Where(p => p is not null)) await pool.DisposeAsync();
            throw;
        }
    }
}

internal sealed class HistoricalPushRun(HistoricalPushSource[] sources, IMqttPushPool[] pools,
    HistoricalPushRequest request, DateTimeOffset from, DateTimeOffset to,
    Func<MeterRef, CancellationToken, Task<bool>> allow, Diagnostics.SimulatorMetrics metrics) : IAsyncDisposable
{
    private int _used;

    internal static DateTimeOffset FirstSlot(DateTimeOffset from, int seconds)
    {
        long ticks = checked(seconds * TimeSpan.TicksPerSecond);
        long first = checked((from.UtcTicks + ticks - 1) / ticks * ticks);
        return new DateTimeOffset(first, TimeSpan.Zero);
    }

    internal static long SlotCount(DateTimeOffset from, DateTimeOffset to, int seconds)
    {
        var first = FirstSlot(from, seconds);
        return first > to ? 0 : (to.UtcTicks - first.UtcTicks) / (seconds * TimeSpan.TicksPerSecond) + 1;
    }

    public async Task<HistoricalPushProgress> SendAsync(Action<HistoricalPushProgress> progress, CancellationToken token)
    {
        if (Interlocked.Exchange(ref _used, 1) != 0) throw new InvalidOperationException("This run was already consumed.");
        long total = sources.Sum(s => checked(SlotCount(from, to, s.PeriodSeconds) * s.Count));
        long sent = 0, skipped = 0, failed = 0, messages = 0, rejected = 0;
        string? error = null;
        long readingTicks = 0;
        var watch = Stopwatch.StartNew();
        var limiter = new MqttPublishRateLimiter(request.RecordsPerSecond);
        var queue = new PriorityQueue<(HistoricalPushSource Source, DateTimeOffset Time), DateTimeOffset>();
        foreach (var source in sources)
        {
            var first = FirstSlot(from, source.PeriodSeconds);
            if (first <= to) queue.Enqueue((source, first), first);
        }
        HistoricalPushProgress Snapshot()
        {
            long ticks = Interlocked.Read(ref readingTicks);
            return new(from, to, total, Interlocked.Read(ref sent), Interlocked.Read(ref skipped),
                Interlocked.Read(ref failed), Interlocked.Read(ref messages), Interlocked.Read(ref rejected), watch.Elapsed,
                ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero), error);
        }
        using var reporting = CancellationTokenSource.CreateLinkedTokenSource(token);
        var reporter = ReportAsync();
        try
        {
            progress(Snapshot());
            while (queue.TryDequeue(out var slot, out _))
            {
                token.ThrowIfCancellationRequested();
                var source = slot.Source;
                if (!source.IsCurrent()) throw new InvalidOperationException($"Batch {source.BatchId} or its destination changed. Start a new run.");
                Interlocked.Exchange(ref readingTicks, slot.Time.UtcTicks);
                await Parallel.ForEachAsync(Meters(source), new ParallelOptions { MaxDegreeOfParallelism = request.MaxConcurrency, CancellationToken = token }, async (meter, ct) =>
                {
                    await limiter.WaitAsync(ct);
                    if (!source.IsCurrent()) throw new InvalidOperationException($"Batch {source.BatchId} or its destination changed.");
                    if (!await allow(meter, ct))
                    {
                        Interlocked.Increment(ref skipped);
                        metrics.RecordPushSkipped(source.Nic);
                        return;
                    }
                    if (!source.IsCurrent()) throw new InvalidOperationException($"Batch {source.BatchId} or its destination changed.");
                    long started = Stopwatch.GetTimestamp();
                    try
                    {
                        var result = await source.Send(meter, slot.Time, ct);
                        Interlocked.Add(ref messages, result.Sent);
                        Interlocked.Add(ref rejected, result.Failed);
                        metrics.RecordPushPayloads(source.Nic, result.Sent, result.Failed);
                        bool ok = result.Sent > 0 && result.Failed == 0;
                        if (ok) Interlocked.Increment(ref sent);
                        else { Interlocked.Increment(ref failed); Interlocked.CompareExchange(ref error, result.Error ?? "No payload delivered.", null); }
                        metrics.RecordPushMeter(source.Nic, ok, Stopwatch.GetElapsedTime(started));
                    }
                    catch (PushCanceledException ex)
                    {
                        Interlocked.Add(ref messages, ex.Sent);
                        Interlocked.Add(ref rejected, ex.Failed);
                        Interlocked.Increment(ref failed);
                        metrics.RecordPushPayloads(source.Nic, ex.Sent, ex.Failed);
                        metrics.RecordPushMeter(source.Nic, false, Stopwatch.GetElapsedTime(started));
                        throw;
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref failed);
                        Interlocked.CompareExchange(ref error, ex.Message, null);
                        metrics.RecordPushMeter(source.Nic, false, Stopwatch.GetElapsedTime(started));
                    }
                });
                var next = slot.Time.AddSeconds(source.PeriodSeconds);
                if (next <= to) queue.Enqueue((source, next), next);
            }
            return Snapshot();
        }
        finally
        {
            reporting.Cancel();
            await reporter;
            progress(Snapshot());
        }

        async Task ReportAsync()
        {
            try { while (true) { await Task.Delay(500, reporting.Token); progress(Snapshot()); } }
            catch (OperationCanceledException) when (reporting.IsCancellationRequested) { }
        }
    }

    private static IEnumerable<MeterRef> Meters(HistoricalPushSource source)
    {
        for (long i = 0; i < source.Count; i++) yield return new(source.StartIndex + i, source.Nic);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var pool in pools) await pool.DisposeAsync();
    }
}
