using System.Collections.Concurrent;
using System.Diagnostics;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Push;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Brain;

public sealed record MqttPushRequest
{
    public IReadOnlyList<int> BatchIds { get; init; } = [];
    public int PublisherCount { get; init; } = 8;
    public int Qos { get; init; } = 2;
    public int MaxConcurrency { get; init; } = 64;
    public int? MaximumMetersPerBatch { get; init; }
    public bool SelectRandomly { get; init; }
    public string? PushSetupLogicalName { get; init; }
    public int ChunkSize { get; init; }
    public int ChunkIntervalSeconds { get; init; }
    public int PreparedMemoryMiB { get; init; } = 256;
    public int? PublishesPerSecond { get; init; }

    public void Validate()
    {
        if (PublishesPerSecond is { } rate) MqttPublishRateLimiter.Validate(rate);
        if (BatchIds.Count == 0 || BatchIds.Distinct().Count() != BatchIds.Count)
            throw new ArgumentException("Select at least one batch, without duplicates.");
        if (PublisherCount is < 1 or > MqttPushPool.MaximumPublisherCount)
            throw new ArgumentException($"Publishers must be between 1 and {MqttPushPool.MaximumPublisherCount} per broker/transport.");
        if (Qos is < 0 or > 2) throw new ArgumentException("QoS must be 0, 1 or 2.");
        if (MaxConcurrency < PublisherCount || MaxConcurrency > 1024)
            throw new ArgumentException("Concurrent meters must be at least the publisher count and at most 1024.");
        if (MaximumMetersPerBatch is <= 0) throw new ArgumentException("Meter limit must be positive, or empty for all meters.");
        if (ChunkSize is < 0 or > 1_000_000 || ChunkIntervalSeconds is < 0 or > 3600)
            throw new ArgumentException("Wave size must be 0 to 1,000,000 and its pause 0 to 3600 seconds.");
        if (PreparedMemoryMiB is < 1 or > 16_384) throw new ArgumentException("Prepared memory must be 1 to 16384 MiB.");
    }
}

public sealed record MqttPushSummary(long MetersSent, long MetersFailed, long MetersSkipped,
    long MessagesSent, long MessagesFailed, TimeSpan SendTime, string? Error);

public sealed record MqttLoopOptions
{
    /// <summary>Zero runs until stopped. The duration includes publishing and cycle pauses.</summary>
    public int DurationMinutes { get; init; }
    public int CyclePauseSeconds { get; init; }

    public void Validate()
    {
        if (DurationMinutes is < 0 or > 10080) throw new ArgumentException("Loop duration must be 0 (until stopped) to 10080 minutes.");
        if (CyclePauseSeconds is < 0 or > 3600) throw new ArgumentException("Cycle pause must be 0 to 3600 seconds.");
    }
}

public sealed record MqttLoopSummary(long CompletedCycles, MqttPushSummary Totals);

internal sealed record MqttPushSource(int BatchId, long Count, BrokerBinding Binding,
    Func<IEnumerable<MeterRef>> Meters, Func<MeterRef, IReadOnlyList<NicPublish>> Build,
    Func<bool> IsCurrent,
    Func<MeterRef, CancellationToken, Task<bool>>? Allow = null,
    Func<MeterRef, DateTimeOffset?, IReadOnlyList<NicPublish>>? BuildAt = null,
    Func<MeterRef, CancellationToken, ValueTask<IDisposable>>? Acquire = null);

/// <summary>
/// A run with preconnected publishers. Prepared bytes are consumed once; live loops rebuild each cycle. Dispose after
/// preparation/sending has stopped; cancellation interrupts outstanding publishes and pool waits.
/// No broker polling or throughput sampling is performed here.
/// </summary>
public sealed class MqttPushRun : IAsyncDisposable
{
    private readonly MqttPushSource[] _sources;
    private readonly IReadOnlyDictionary<BrokerBinding, IMqttPushPool> _pools;
    private readonly MqttPushRequest _request;
    private readonly MqttPublishRateLimiter? _rateLimiter;
    private readonly CancellationTokenSource _stop;
    private readonly Action<Action> _unsubscribe;
    private readonly bool _ciphering;
    private PreparedMeter[]? _prepared;
    private int _state; // 0 new, 1 preparing, 2 ready, 3 sending, 4 consumed/failed
    private int _disposed;
    private long _preparedBytes;
    private long _preparedMessages;
    private long _preparedMeters;
    private string? _invalidReason;
    private readonly object _lifetimeSync = new();
    private readonly SimulatorMetrics? _metrics;
    private readonly IDisposable? _batchLease;
    public MqttLoopSummary? LoopResult { get; private set; }
    private MqttPushSummary? _lastPass;

    internal MqttPushRun(MqttPushSource[] sources, IReadOnlyDictionary<BrokerBinding, IMqttPushPool> pools,
        MqttPushRequest request, bool ciphering, CancellationTokenSource stop,
        Action<Action> subscribe, Action<Action> unsubscribe, SimulatorMetrics? metrics = null, IDisposable? batchLease = null)
    {
        _sources = sources;
        _pools = pools;
        _request = request;
        _rateLimiter = request.PublishesPerSecond is { } rate ? new(rate) : null;
        _ciphering = ciphering;
        _stop = stop;
        _unsubscribe = unsubscribe;
        _metrics = metrics;
        _batchLease = batchLease;
        subscribe(CheckConfiguration);
        CheckConfiguration();
    }

    public long TotalMeters => _sources.Sum(s => s.Count);
    public int? PublishesPerSecond => _rateLimiter?.Rate;
    public void SetPublishRate(int rate) => (_rateLimiter
        ?? throw new InvalidOperationException("This run was opened without a publish rate limit.")).SetRate(rate);
    public long PreparedBytes => Interlocked.Read(ref _preparedBytes);
    public long PreparedMessages => Interlocked.Read(ref _preparedMessages);
    public long PreparedMeters => Interlocked.Read(ref _preparedMeters);
    public DateTimeOffset? PreparedAtUtc { get; private set; }
    public TimeSpan PreparationTime { get; private set; }
    public bool IsReady => _state == 2 && !_stop.IsCancellationRequested && _pools.Values.All(p => p.IsConnected);
    public string? InvalidReason => _invalidReason;

    public void Stop() { lock (_lifetimeSync) if (_disposed == 0) _stop.Cancel(); }

    private void CheckConfiguration()
    {
        lock (_lifetimeSync)
        {
            if (_disposed != 0 || _sources.All(s => s.IsCurrent())) return;
            _invalidReason = "A selected batch or broker changed. Create a new run.";
            _stop.Cancel();
        }
    }

    private void CheckReadyToWork()
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        CheckConfiguration();
        if (_invalidReason is not null) throw new InvalidOperationException(_invalidReason);
        _stop.Token.ThrowIfCancellationRequested();
        if (!_pools.Values.All(p => p.IsConnected))
            throw new InvalidOperationException("A publishing connection disconnected. Create a new run.");
    }

    public async Task PrepareAsync()
    {
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0) throw new InvalidOperationException("This run has already been used.");
        var sw = Stopwatch.StartNew();
        var generatedFromUtc = DateTimeOffset.UtcNow;
        var prepared = new ConcurrentBag<PreparedMeter>();
        try
        {
            CheckReadyToWork();
            // A pull can advance a session's invocation counter while bytes wait in RAM. Live
            // generation remains available; never cache ciphered frames across that interval.
            if (_ciphering) throw new InvalidOperationException("Prepared mode requires Push:UseCiphering=false. Use live generation for ciphered pushes.");
            await Parallel.ForEachAsync(Meters(), new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Min(_request.MaxConcurrency, Math.Max(1, Environment.ProcessorCount)),
                CancellationToken = _stop.Token,
            }, (item, ct) =>
            {
                ct.ThrowIfCancellationRequested();
                IReadOnlyList<NicPublish> messages = item.Source.Build(item.Meter);
                // Includes conservative per-array, topic, message and meter bookkeeping estimates.
                // Session/template memory and the bounded workers' temporary buffers are separate.
                long bytes = 128 + messages.Sum(m => m.Payload.LongLength + 2L * m.Topic.Length + 160);
                if (Interlocked.Add(ref _preparedBytes, bytes) > _request.PreparedMemoryMiB * 1024L * 1024L)
                    throw new InvalidOperationException("Prepared dataset exceeded its memory budget. Select fewer meters or increase Prepared memory.");
                prepared.Add(new PreparedMeter(item.Source.Binding, item.Meter.Nic, messages, item.Source, item.Meter));
                Interlocked.Increment(ref _preparedMeters);
                Interlocked.Add(ref _preparedMessages, messages.Count);
                return ValueTask.CompletedTask;
            });
            CheckReadyToWork();
            if (PreparedMessages == 0) throw new InvalidOperationException("The selected meters/profile produced no MQTT messages.");
            _prepared = prepared.ToArray();
            PreparedAtUtc = generatedFromUtc;
            PreparationTime = sw.Elapsed;
            Volatile.Write(ref _state, 2);
        }
        catch
        {
            _prepared = null;
            Volatile.Write(ref _state, 4);
            throw;
        }
    }

    public Task<MqttPushSummary> SendLiveAsync() => SendAsync(prepared: false);
    public Task<MqttPushSummary> FireAsync() => SendAsync(prepared: true);

    private async Task<MqttPushSummary> SendAsync(bool prepared)
    {
        int expectedState = prepared ? 2 : 0;
        if (Interlocked.CompareExchange(ref _state, 3, expectedState) != expectedState)
            throw new InvalidOperationException("This run is not ready or has already been consumed. Prepare a new dataset.");
        try { return await SendPassAsync(prepared, _stop.Token); }
        finally { _prepared = null; Volatile.Write(ref _state, 4); }
    }

    /// <summary>Reuses connections, regenerates every pass, and retains only cumulative totals.</summary>
    public async Task<MqttLoopSummary> SendLoopAsync(MqttLoopOptions options)
    {
        options.Validate();
        if (Interlocked.CompareExchange(ref _state, 3, 0) != 0)
            throw new InvalidOperationException("This run has already been used.");
        using var duration = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
        if (options.DurationMinutes > 0) duration.CancelAfter(TimeSpan.FromMinutes(options.DurationMinutes));
        var sw = Stopwatch.StartNew();
        long cycles = 0;
        var totals = new MqttPushSummary(0, 0, 0, 0, 0, TimeSpan.Zero, null);
        try
        {
            while (true)
            {
                duration.Token.ThrowIfCancellationRequested();
                _lastPass = null;
                MqttPushSummary pass;
                try
                {
                    pass = await SendPassAsync(false, duration.Token);
                    cycles++;
                }
                finally
                {
                    // SendPass also snapshots confirmed work if Stop interrupts a fleet pass.
                    if (_lastPass is { } done)
                        totals = new MqttPushSummary(totals.MetersSent + done.MetersSent,
                            totals.MetersFailed + done.MetersFailed, totals.MetersSkipped + done.MetersSkipped,
                            totals.MessagesSent + done.MessagesSent, totals.MessagesFailed + done.MessagesFailed,
                            sw.Elapsed, totals.Error ?? done.Error);
                    LoopResult = new MqttLoopSummary(cycles, totals with { SendTime = sw.Elapsed });
                }
                if (pass.MessagesSent == 0 && (pass.MetersFailed > 0 || pass.MetersSkipped == 0))
                    throw new InvalidOperationException(pass.Error ?? "The selected meters/profiles produced no successful MQTT publishes. Loop stopped.");
                if (pass.MessagesSent == 0 && options.CyclePauseSeconds == 0)
                    await Task.Delay(100, duration.Token);
                if (options.CyclePauseSeconds > 0)
                    await Task.Delay(TimeSpan.FromSeconds(options.CyclePauseSeconds), duration.Token);
            }
        }
        catch (OperationCanceledException) when (duration.IsCancellationRequested && !_stop.IsCancellationRequested)
        {
            // A configured duration is successful completion; explicit Stop remains cancellation.
        }
        finally
        {
            LoopResult = new MqttLoopSummary(cycles, totals with { SendTime = sw.Elapsed });
            Volatile.Write(ref _state, 4);
        }
        return LoopResult;
    }

    private async Task<MqttPushSummary> SendPassAsync(bool prepared, CancellationToken cancellationToken)
    {
        long metersSent = 0, metersFailed = 0, skipped = 0, messagesSent = 0, messagesFailed = 0;
        string? firstError = null;
        var sw = Stopwatch.StartNew();
        try
        {
            CheckReadyToWork();
            if (prepared && DateTimeOffset.UtcNow - PreparedAtUtc > TimeSpan.FromMinutes(5))
                throw new InvalidOperationException("Prepared payloads are older than five minutes. Prepare a fresh dataset.");

            IEnumerable<Work> work = prepared
                ? _prepared!.Select(item => new Work(null, default, item))
                : Meters().Select(item => new Work(item.Source, item.Meter, null));
            // Prepared fire is a single wave. Live generation can retain the existing pacing.
            IEnumerable<IEnumerable<Work>> waves = !prepared && _request.ChunkSize > 0
                ? work.Chunk(_request.ChunkSize) : [work];
            bool firstWave = true;
            foreach (var wave in waves)
            {
                if (!firstWave && _request.ChunkIntervalSeconds > 0)
                    await Task.Delay(TimeSpan.FromSeconds(_request.ChunkIntervalSeconds), cancellationToken);
                firstWave = false;
                await Parallel.ForEachAsync(wave, new ParallelOptions
                {
                    MaxDegreeOfParallelism = _request.MaxConcurrency,
                    CancellationToken = cancellationToken,
                }, async (workItem, ct) =>
                {
                    long started = Stopwatch.GetTimestamp();
                    NicType nic = workItem.Prepared?.Nic ?? workItem.Meter.Nic;
                    try
                    {
                        var source = workItem.Prepared?.Source ?? workItem.Source!;
                        var meter = workItem.Prepared?.Meter ?? workItem.Meter;
                        if (source.Allow is { } allow && !await allow(meter, ct))
                        {
                            Interlocked.Increment(ref skipped);
                            _metrics?.RecordPushSkipped(nic);
                            return;
                        }
                        using var gate = source.Acquire is { } acquire ? await acquire(meter, ct) : null;
                        PreparedMeter item = workItem.Prepared ?? new PreparedMeter(workItem.Source!.Binding, nic,
                            workItem.Source.Build(workItem.Meter), workItem.Source, workItem.Meter);
                        if (item.Messages.Count == 0)
                        {
                            Interlocked.Increment(ref skipped);
                            _metrics?.RecordPushSkipped(nic);
                            return;
                        }
                        var delivery = await _pools[item.Binding].PublishMeterAsync(item.Messages, ct, _rateLimiter);
                        Interlocked.Add(ref messagesSent, delivery.Sent);
                        Interlocked.Add(ref messagesFailed, delivery.Failed);
                        _metrics?.RecordPushPayloads(nic, delivery.Sent, delivery.Failed);
                        if (delivery.Failed == 0) Interlocked.Increment(ref metersSent);
                        else Interlocked.Increment(ref metersFailed);
                        if (delivery.Error is not null) Interlocked.CompareExchange(ref firstError, delivery.Error, null);
                        _metrics?.RecordPushMeter(nic, delivery.Failed == 0, Stopwatch.GetElapsedTime(started));
                    }
                    catch (PushCanceledException ex)
                    {
                        Interlocked.Add(ref messagesSent, ex.Sent);
                        Interlocked.Add(ref messagesFailed, ex.Failed);
                        Interlocked.Increment(ref metersFailed);
                        _metrics?.RecordPushPayloads(nic, ex.Sent, ex.Failed);
                        _metrics?.RecordPushMeter(nic, false, Stopwatch.GetElapsedTime(started));
                        throw;
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref metersFailed);
                        Interlocked.CompareExchange(ref firstError, ex.Message, null);
                        _metrics?.RecordPushMeter(nic, false, Stopwatch.GetElapsedTime(started));
                    }
                });
            }
            return new MqttPushSummary(metersSent, metersFailed, skipped, messagesSent, messagesFailed, sw.Elapsed, firstError);
        }
        finally
        {
            _lastPass = new MqttPushSummary(metersSent, metersFailed, skipped, messagesSent, messagesFailed, sw.Elapsed, firstError);
        }
    }

    private IEnumerable<(MqttPushSource Source, MeterRef Meter)> Meters()
    {
        // Round-robin keeps every selected broker supplied instead of draining batches serially.
        var enumerators = _sources.Select(s => s.Meters().GetEnumerator()).ToArray();
        var finished = new bool[enumerators.Length];
        int remaining = enumerators.Length;
        try
        {
            while (remaining > 0)
            {
                for (int i = 0; i < enumerators.Length; i++)
                {
                    _stop.Token.ThrowIfCancellationRequested();
                    if (finished[i]) continue;
                    if (enumerators[i].MoveNext()) yield return (_sources[i], enumerators[i].Current);
                    else { finished[i] = true; remaining--; }
                }
            }
        }
        finally { foreach (var enumerator in enumerators) enumerator.Dispose(); }
    }

    public async ValueTask DisposeAsync()
    {
        lock (_lifetimeSync)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _unsubscribe(CheckConfiguration);
            _stop.Cancel();
        }
        _prepared = null;
        try { await Task.WhenAll(_pools.Values.Select(async p => await p.DisposeAsync())); }
        finally { _stop.Dispose(); _batchLease?.Dispose(); }
    }

    private sealed record PreparedMeter(BrokerBinding Binding, NicType Nic, IReadOnlyList<NicPublish> Messages,
        MqttPushSource Source, MeterRef Meter);
    private readonly record struct Work(MqttPushSource? Source, MeterRef Meter, PreparedMeter? Prepared);
}
