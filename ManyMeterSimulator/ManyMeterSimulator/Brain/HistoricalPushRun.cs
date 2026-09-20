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
    public int MaxConcurrency { get; init; } = 256;
    public int RecordsPerSecond { get; init; }
    public int PublisherCount { get; init; } = MqttPushPool.MaximumPublisherCount;
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
        if (RecordsPerSecond != 0) MqttPublishRateLimiter.Validate(RecordsPerSecond);
    }
}

public sealed record HistoricalPushProgress(DateTimeOffset From, DateTimeOffset To, long Total,
    long Sent = 0, long Skipped = 0, long Failed = 0, long MessagesSent = 0, long MessagesFailed = 0,
    TimeSpan Elapsed = default, DateTimeOffset? ReadingTime = null, string? Error = null)
{
    public HistoricalSlotProgress? CurrentSlot { get; init; }
    public HistoricalPushPosition? LastSuccessfulPush { get; init; }
    public IReadOnlyList<HistoricalProfileProgress> Profiles { get; init; } = [];
    public double CurrentRecordsPerSecond { get; init; }
    public double CurrentMessagesPerSecond { get; init; }
    public double RateWindowSeconds { get; init; }

    public long Processed => Sent + Skipped + Failed;
    public double RecordsPerSecond => Elapsed.TotalSeconds > 0 ? Sent / Elapsed.TotalSeconds : 0;
}

internal sealed record HistoricalPushSource(int BatchId, long StartIndex, long Count, NicType Nic,
    string Profile, int PeriodSeconds, Func<bool> IsCurrent,
    Func<MeterRef, DateTimeOffset, CancellationToken, Task<PushDeliveryResult>> Send, string? BatchName = null);

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
            if (batch.Status != BatchStatus.Running)
            {
                throw new InvalidOperationException($"Start batch '{batch.Name}' first.");
            }

            int blockSeconds;
            if (batch.NicType == NicType.MqttWirepas)
            {
                blockSeconds = checked(_customPullOptions.GetBlockPeriodMinutes(batch.HesTemplateId
                    ?? throw new InvalidOperationException("Missing HES template.")) * 60);
            }
            else
            {
                var session = _sessions.GetOrCreate(new MeterRef(batch.StartIndex, batch.NicType));
                lock (session)
                {
                    blockSeconds = session.BlockPushPeriodSeconds;
                }
            }

            foreach (var (profile, seconds) in new[] { ("0.0.25.9.0.255", request.InstantaneousIntervalMinutes * 60), ("0.5.25.9.0.255", blockSeconds) })
            {
                if (batch.NicType == NicType.Tcp4G)
                {
                    var source = ResolveTcpSource(id, new TcpPushRequest { BatchIds = [id], PushSetupLogicalName = profile }, _options.UseCiphering);
                    sources.Add(new(id, batch.StartIndex, batch.Count, batch.NicType, profile, seconds, source.IsCurrent,
                        (meter, time, ct) => source.Send(meter, source.BuildAt!(meter, time), ct), batch.Name));
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
                        }, batch.Name));
                }
            }
        }

        try
        {
            foreach (var binding in pools.Keys.ToArray())
            {
                pools[binding] = await _mqtt.OpenPoolAsync(binding, request.PublisherCount, request.Qos, _options.PublishTimeoutSeconds, token);
            }

            token.ThrowIfCancellationRequested();
            return new HistoricalPushRun(sources.ToArray(), pools.Values.ToArray(), request, start, end,
                (meter, ct) => AllowPushAsync(meter, ct, simulateNetworkDelay: false), _metrics);
        }
        catch
        {
            foreach (var pool in pools.Values.Where(p => p is not null))
            {
                await pool.DisposeAsync();
            }

            throw;
        }
    }
}

internal sealed class HistoricalPushRun(HistoricalPushSource[] sources, IMqttPushPool[] pools,
    HistoricalPushRequest request, DateTimeOffset from, DateTimeOffset to,
    Func<MeterRef, CancellationToken, Task<bool>> allow, Diagnostics.SimulatorMetrics metrics) : IAsyncDisposable
{
    private int _used;
    private MqttPublishRateLimiter? _limiter = request.RecordsPerSecond == 0 ? null : new(request.RecordsPerSecond);

    public int RecordsPerSecond => Volatile.Read(ref _limiter)?.Rate ?? 0;

    public void SetRecordsPerSecond(int rate)
    {
        if (rate != 0) MqttPublishRateLimiter.Validate(rate);
        Interlocked.Exchange(ref _limiter, rate == 0 ? null : new MqttPublishRateLimiter(rate));
    }

    private async ValueTask WaitForRateAsync(CancellationToken token)
    {
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var limiter = Volatile.Read(ref _limiter);
            if (limiter is null || limiter.TryAcquire(out var delay)) return;
            await Task.Delay(delay, token);
        }
    }

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
        if (Interlocked.Exchange(ref _used, 1) != 0)
        {
            throw new InvalidOperationException("This run was already consumed.");
        }

        var telemetry = new HistoricalPushTelemetry(sources, from, to);
        var watch = Stopwatch.StartNew();
        var queue = new PriorityQueue<(HistoricalPushSource Source, DateTimeOffset Time), DateTimeOffset>();
        foreach (var source in sources)
        {
            var first = FirstSlot(from, source.PeriodSeconds);
            if (first <= to)
            {
                queue.Enqueue((source, first), first);
            }
        }

        using var reporting = CancellationTokenSource.CreateLinkedTokenSource(token);
        progress(telemetry.Snapshot(watch.Elapsed));
        var reporter = ReportAsync();
        try
        {
            while (queue.TryDequeue(out var slot, out _))
            {
                token.ThrowIfCancellationRequested();
                var source = slot.Source;
                if (!source.IsCurrent())
                {
                    throw new InvalidOperationException($"Batch {source.BatchId} or its destination changed. Start a new run.");
                }

                telemetry.BeginSlot(source, slot.Time);
                await Parallel.ForEachAsync(Meters(source), new ParallelOptions
                {
                    MaxDegreeOfParallelism = request.MaxConcurrency,
                    CancellationToken = token
                }, async (meter, ct) =>
                {
                    await WaitForRateAsync(ct);
                    if (!source.IsCurrent())
                    {
                        throw new InvalidOperationException($"Batch {source.BatchId} or its destination changed.");
                    }

                    if (!await allow(meter, ct))
                    {
                        telemetry.Record(source, slot.Time, skipped: 1);
                        metrics.RecordPushSkipped(source.Nic);
                        return;
                    }

                    if (!source.IsCurrent())
                    {
                        throw new InvalidOperationException($"Batch {source.BatchId} or its destination changed.");
                    }

                    long started = Stopwatch.GetTimestamp();
                    telemetry.Sending(1);
                    try
                    {
                        var result = await source.Send(meter, slot.Time, ct);
                        bool ok = result.Sent > 0 && result.Failed == 0;
                        telemetry.Record(source, slot.Time, sent: ok ? 1 : 0, failed: ok ? 0 : 1,
                            messages: result.Sent, rejected: result.Failed,
                            error: ok ? null : result.Error ?? "No payload delivered.");
                        metrics.RecordPushPayloads(source.Nic, result.Sent, result.Failed);
                        metrics.RecordPushMeter(source.Nic, ok, Stopwatch.GetElapsedTime(started));
                    }
                    catch (PushCanceledException ex)
                    {
                        telemetry.Record(source, slot.Time, failed: 1, messages: ex.Sent, rejected: ex.Failed);
                        metrics.RecordPushPayloads(source.Nic, ex.Sent, ex.Failed);
                        metrics.RecordPushMeter(source.Nic, false, Stopwatch.GetElapsedTime(started));
                        throw;
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        telemetry.Record(source, slot.Time, failed: 1, error: ex.Message);
                        metrics.RecordPushMeter(source.Nic, false, Stopwatch.GetElapsedTime(started));
                    }
                    finally
                    {
                        telemetry.Sending(-1);
                    }
                });

                var next = slot.Time.AddSeconds(source.PeriodSeconds);
                if (next <= to)
                {
                    queue.Enqueue((source, next), next);
                }
            }
        }
        finally
        {
            reporting.Cancel();
            await reporter;
            watch.Stop();
            progress(telemetry.Snapshot(watch.Elapsed, finished: true));
        }

        return telemetry.Snapshot(watch.Elapsed, finished: true);

        async Task ReportAsync()
        {
            try
            {
                while (true)
                {
                    await Task.Delay(500, reporting.Token);
                    progress(telemetry.Snapshot(watch.Elapsed));
                }
            }
            catch (OperationCanceledException) when (reporting.IsCancellationRequested)
            {
            }
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
