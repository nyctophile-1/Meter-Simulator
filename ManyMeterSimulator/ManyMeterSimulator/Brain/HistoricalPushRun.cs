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
    public DateTimeOffset? EndTimeUtc { get; init; }

    public void Validate()
    {
        if (BatchIds.Count == 0 || BatchIds.Distinct().Count() != BatchIds.Count)
        {
            throw new ArgumentException("Select at least one batch, without duplicates.");
        }

        if (Days is < 1 or > 3650)
        {
            throw new ArgumentException("Days must be 1 to 3650.");
        }

        if (InstantaneousIntervalMinutes is < 1 or > 1440)
        {
            throw new ArgumentException("Instantaneous interval must be 1 to 1440 minutes.");
        }

        if (MaxConcurrency is < 1 or > 1024)
        {
            throw new ArgumentException("Concurrency must be 1 to 1024.");
        }

        if (RecordsPerSecond != 0)
        {
            MqttPublishRateLimiter.Validate(RecordsPerSecond);
        }
    }

    internal void ValidateMqtt()
    {
        if (PublisherCount is < 1 or > 256 || PublisherCount > MaxConcurrency)
        {
            throw new ArgumentException("Publishers must be 1 to 256 and no more than concurrency.");
        }

        if (Qos is < 0 or > 2)
        {
            throw new ArgumentException("QoS must be 0, 1 or 2.");
        }
    }
}

public sealed record HistoricalPushProgress(DateTimeOffset From, DateTimeOffset To, long Total,
    long Sent = 0, long Skipped = 0, long Failed = 0, long MessagesSent = 0, long MessagesFailed = 0,
    TimeSpan Elapsed = default, DateTimeOffset? ReadingTime = null, string? Error = null)
{
    public HistoricalSlotProgress? CurrentSlot { get; init; }
    public IReadOnlyList<HistoricalSlotProgress> CurrentSlots { get; init; } = [];
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
    Func<MeterRef, DateTimeOffset, CancellationToken, Task<PushDeliveryResult>> Send,
    string? BatchName = null, string? ResumeIdentity = null)
{
    public string Identity => ResumeIdentity ?? $"{BatchId}:{StartIndex}:{Count}:{Nic}:{Profile}:{PeriodSeconds}";
}

public sealed partial class PushCoordinator
{
    private string HistoricalIdentity(MeterBatch batch, string profile, int period)
    {
        object? destination;
        if (batch.NicType == NicType.Tcp4G)
        {
            TryResolveDestination(batch, null, out var endpoint, out _);
            destination = new { endpoint, _options.DefaultPort, _options.RequireMeterSourceIp };
        }
        else
        {
            var broker = _network.Broker(batch.EnvironmentKey!);
            destination = broker is null ? null : new { broker.Host, broker.Port, broker.Username, broker.UseTls };
        }

        var bytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
        {
            batch.Id, batch.CreatedAtUtc, batch.StartIndex, batch.Count, batch.NicType,
            batch.TemplateName, batch.HesTemplateId, batch.CustomPushHeaderKind, batch.EnvironmentKey,
            profile, period, destination, _options.UseCiphering
        });
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
    }

    internal async Task<HistoricalPushRun> OpenHistoricalRunAsync(HistoricalPushRequest request, CancellationToken token, HistoricalPushCheckpoint? resume = null)
    {
        request = request with { BatchIds = request.BatchIds.ToArray() };
        request.Validate();

        var now = _clock.GetUtcNow();
        var end = resume?.Progress.To ?? request.EndTimeUtc?.ToUniversalTime() ?? now;
        if (end > now)
        {
            throw new ArgumentException("The historical end time cannot be in the future.");
        }

        var start = resume?.Progress.From ?? end.AddDays(-request.Days);
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

            if (batch.NicType != NicType.Tcp4G)
            {
                request.ValidateMqtt();
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
                        (meter, time, ct) => source.Send(meter, source.BuildAt!(meter, time), ct), batch.Name, HistoricalIdentity(batch, profile, seconds)));
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
                        }, batch.Name, HistoricalIdentity(batch, profile, seconds)));
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
                (meter, ct) => AllowPushAsync(meter, ct, simulateNetworkDelay: false), _metrics, resume);
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
    Func<MeterRef, CancellationToken, Task<bool>> allow, Diagnostics.SimulatorMetrics metrics, HistoricalPushCheckpoint? resume = null) : IAsyncDisposable
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

    public async Task<HistoricalPushProgress> SendAsync(Action<HistoricalPushProgress> progress, CancellationToken token,
        Action<HistoricalPushCheckpoint>? checkpoint = null)
    {
        if (Interlocked.Exchange(ref _used, 1) != 0)
        {
            throw new InvalidOperationException("This run was already consumed.");
        }

        if (resume is not null && (resume.Version != 1 || resume.Sources.Length != sources.Length ||
            sources.Where((source, index) => source.Identity != resume.Sources[index].Identity).Any()))
        {
            throw new InvalidOperationException("The saved batches, profiles or destinations changed. Start a new historical run.");
        }

        var cursors = sources.Select((source, index) => new HistoricalPushCursor(source, from, to,
            resume?.Sources[index])).ToArray();
        foreach (var cursor in cursors)
        {
            cursor.Validate();
        }

        if (resume is not null && (resume.Progress.Total != cursors.Sum(c => c.Total) ||
            resume.Progress.Processed != resume.Sources.Sum(c => c.NextRecord + c.CompletedAhead.LongLength)))
        {
            throw new InvalidOperationException("The saved historical counts do not match its meter positions.");
        }

        var telemetry = new HistoricalPushTelemetry(sources, from, to, resume?.Progress);
        var previousElapsed = resume?.Progress.Elapsed ?? TimeSpan.Zero;
        var watch = Stopwatch.StartNew();
        var lastSaved = TimeSpan.Zero;
        long turn = 0;
        var queue = new PriorityQueue<(HistoricalPushCursor Cursor, long Ordinal), (DateTimeOffset Time, long Turn)>();
        foreach (var cursor in cursors.Where(c => c.Next < c.Total))
        {
            queue.Enqueue((cursor, cursor.Next), (cursor.Time(cursor.Next), turn++));
        }

        void SaveCheckpoint()
        {
            checkpoint?.Invoke(new(1, request, telemetry.Snapshot(previousElapsed + watch.Elapsed),
                cursors.Select(c => c.Snapshot()).ToArray(), DateTimeOffset.UtcNow));
            lastSaved = watch.Elapsed;
        }

        using var reporting = CancellationTokenSource.CreateLinkedTokenSource(token);
        progress(telemetry.Snapshot(previousElapsed + watch.Elapsed));
        var reporter = ReportAsync();
        try
        {
            SaveCheckpoint();
            while (queue.TryPeek(out _, out var priority))
            {
                token.ThrowIfCancellationRequested();
                var time = priority.Time;
                var chunk = new List<(HistoricalPushCursor Cursor, long Ordinal)>();
                int chunkSize = Math.Max(256, request.MaxConcurrency * 2);
                while (chunk.Count < chunkSize && queue.TryPeek(out _, out var nextPriority) && nextPriority.Time == time)
                {
                    var work = queue.Dequeue();
                    chunk.Add(work);
                    long next = work.Cursor.Unfinished(work.Ordinal + 1);
                    if (next < work.Cursor.Total)
                    {
                        queue.Enqueue((work.Cursor, next), (work.Cursor.Time(next), turn++));
                    }
                }

                telemetry.BeginSlots(chunk.Select(w => w.Cursor.Source).Distinct().ToArray(), time);
                await Parallel.ForEachAsync(chunk, new ParallelOptions
                {
                    MaxDegreeOfParallelism = request.MaxConcurrency,
                    CancellationToken = token
                }, async (work, ct) =>
                {
                    var cursor = work.Cursor;
                    var source = cursor.Source;
                    var meter = new MeterRef(source.StartIndex + work.Ordinal % source.Count, source.Nic);
                    await WaitForRateAsync(ct);
                    if (!source.IsCurrent())
                    {
                        throw new InvalidOperationException($"Batch {source.BatchId} or its destination changed.");
                    }

                    if (!await allow(meter, ct))
                    {
                        telemetry.Record(source, time, skipped: 1);
                        cursor.Complete(work.Ordinal);
                        metrics.RecordPushSkipped(source.Nic);
                        return;
                    }

                    if (!source.IsCurrent())
                    {
                        throw new InvalidOperationException($"Batch {source.BatchId} or its destination changed.");
                    }

                    long started = Stopwatch.GetTimestamp();
                    telemetry.Sending(source, 1);
                    try
                    {
                        var result = await source.Send(meter, time, ct);
                        bool ok = result.Sent > 0 && result.Failed == 0;
                        telemetry.Record(source, time, sent: ok ? 1 : 0, failed: ok ? 0 : 1,
                            messages: result.Sent, rejected: result.Failed,
                            error: ok ? null : result.Error ?? "No payload delivered.");
                        cursor.Complete(work.Ordinal);
                        metrics.RecordPushPayloads(source.Nic, result.Sent, result.Failed);
                        metrics.RecordPushMeter(source.Nic, ok, Stopwatch.GetElapsedTime(started));
                    }
                    catch (PushCanceledException ex)
                    {
                        if (ex.Sent == 0)
                        {
                            throw;
                        }

                        telemetry.Record(source, time, failed: 1, messages: ex.Sent, rejected: ex.Failed);
                        cursor.Complete(work.Ordinal);
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
                        telemetry.Record(source, time, failed: 1, error: ex.Message);
                        cursor.Complete(work.Ordinal);
                        metrics.RecordPushMeter(source.Nic, false, Stopwatch.GetElapsedTime(started));
                    }
                    finally
                    {
                        telemetry.Sending(source, -1);
                    }
                });

                if (watch.Elapsed - lastSaved >= TimeSpan.FromSeconds(2))
                {
                    SaveCheckpoint();
                }
            }
        }
        finally
        {
            reporting.Cancel();
            await reporter;
            watch.Stop();
            SaveCheckpoint();
            progress(telemetry.Snapshot(previousElapsed + watch.Elapsed, finished: true));
        }

        return telemetry.Snapshot(previousElapsed + watch.Elapsed, finished: true);

        async Task ReportAsync()
        {
            try
            {
                while (true)
                {
                    await Task.Delay(500, reporting.Token);
                    progress(telemetry.Snapshot(previousElapsed + watch.Elapsed));
                }
            }
            catch (OperationCanceledException) when (reporting.IsCancellationRequested)
            {
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var pool in pools) await pool.DisposeAsync();
    }
}
