using System.Collections.Concurrent;
using System.Diagnostics;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;

namespace ManyMeterSimulator.Brain;

public sealed record TcpPushRequest
{
    public IReadOnlyList<int> BatchIds { get; init; } = [];
    public int MaxConcurrency { get; init; } = 256;
    public int? MaximumMetersPerBatch { get; init; }
    public bool SelectRandomly { get; init; }
    public string? PushSetupLogicalName { get; init; }
    public int ChunkSize { get; init; }
    public int ChunkIntervalSeconds { get; init; }
    public int PreparedMemoryMiB { get; init; } = 256;

    public void Validate()
    {
        if (BatchIds.Count == 0 || BatchIds.Distinct().Count() != BatchIds.Count)
            throw new ArgumentException("Select at least one batch, without duplicates.");
        if (MaxConcurrency is < 1 or > 1024) throw new ArgumentException("Concurrent TCP connections must be 1 to 1024.");
        if (MaximumMetersPerBatch is <= 0) throw new ArgumentException("Meter limit must be positive, or empty for all meters.");
        if (ChunkSize is < 0 or > 1_000_000 || ChunkIntervalSeconds is < 0 or > 3600)
            throw new ArgumentException("Wave size must be 0 to 1,000,000 and its pause 0 to 3600 seconds.");
        if (PreparedMemoryMiB is < 1 or > 16_384) throw new ArgumentException("Prepared memory must be 1 to 16384 MiB.");
    }
}

public sealed record TcpPushSummary(long MetersSent, long MetersFailed, long MetersSkipped,
    long MessagesSent, long MessagesFailed, TimeSpan SendTime, string? Error);

public sealed record TcpLoopOptions
{
    public int DurationMinutes { get; init; }
    public int CyclePauseSeconds { get; init; }
    public void Validate()
    {
        if (DurationMinutes is < 0 or > 10080) throw new ArgumentException("Loop duration must be 0 (until stopped) to 10080 minutes.");
        if (CyclePauseSeconds is < 0 or > 3600) throw new ArgumentException("Cycle pause must be 0 to 3600 seconds.");
    }
}

public sealed record TcpLoopSummary(long CompletedCycles, TcpPushSummary Totals);

internal sealed record TcpPushSource(long Count, Func<IEnumerable<MeterRef>> Meters,
    Func<MeterRef, byte[][]> Build,
    Func<MeterRef, byte[][], CancellationToken, Task<PushDeliveryResult>> Send,
    Func<bool> IsCurrent,
    Func<MeterRef, DateTimeOffset?, byte[][]>? BuildAt = null);

public sealed class TcpPushRun : IAsyncDisposable
{
    private readonly TcpPushSource[] _sources;
    private readonly TcpPushRequest _request;
    private readonly bool _ciphering;
    private readonly CancellationTokenSource _stop;
    private readonly Action<Action> _unsubscribe;
    private readonly SimulatorMetrics? _metrics;
    private readonly IDisposable? _batchLease;
    private readonly object _sync = new();
    private PreparedMeter[]? _prepared;
    private int _state;
    private bool _disposed;
    private long _bytes, _messages, _meters;
    private string? _invalidReason;

    internal TcpPushRun(TcpPushSource[] sources, TcpPushRequest request, bool ciphering,
        CancellationToken token, Action<Action> subscribe, Action<Action> unsubscribe, SimulatorMetrics? metrics = null, IDisposable? batchLease = null)
    {
        _sources = sources;
        _request = request;
        _ciphering = ciphering;
        _stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        _unsubscribe = unsubscribe;
        _metrics = metrics;
        _batchLease = batchLease;
        subscribe(CheckConfiguration);
        CheckConfiguration();
    }

    public long TotalMeters => _sources.Sum(s => s.Count);
    public long PreparedBytes => Interlocked.Read(ref _bytes);
    public long PreparedMessages => Interlocked.Read(ref _messages);
    public long PreparedMeters => Interlocked.Read(ref _meters);
    public DateTimeOffset? PreparedAtUtc { get; private set; }
    public TimeSpan PreparationTime { get; private set; }
    public string? InvalidReason => _invalidReason;
    public TcpPushSummary? LastPass { get; private set; }
    public TcpLoopSummary? LoopResult { get; private set; }

    private void CheckConfiguration()
    {
        lock (_sync)
        {
            if (_disposed || _sources.All(s => s.IsCurrent())) return;
            _invalidReason = "A selected batch or TCP target changed. Create a new run.";
            _stop.Cancel();
        }
    }

    private void CheckReady()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        CheckConfiguration();
        if (_invalidReason is not null) throw new InvalidOperationException(_invalidReason);
        _stop.Token.ThrowIfCancellationRequested();
    }

    public async Task PrepareAsync()
    {
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0) throw new InvalidOperationException("This run has already been used.");
        var clock = Stopwatch.StartNew();
        var generated = DateTimeOffset.UtcNow;
        try
        {
            CheckReady();
            if (_ciphering) throw new InvalidOperationException("Prepared mode requires Push:UseCiphering=false. Use live sending for ciphered pushes.");
            var prepared = new ConcurrentBag<PreparedMeter>();
            await Parallel.ForEachAsync(Meters(), new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Min(_request.MaxConcurrency, Math.Max(1, Environment.ProcessorCount)),
                CancellationToken = _stop.Token,
            }, (item, ct) =>
            {
                ct.ThrowIfCancellationRequested();
                byte[][] payloads = item.Source.Build(item.Meter);
                if (Interlocked.Add(ref _bytes, 160 + payloads.Sum(p => p.LongLength + 32)) > _request.PreparedMemoryMiB * 1024L * 1024L)
                    throw new InvalidOperationException("Prepared dataset exceeded its memory budget.");
                prepared.Add(new(item.Source, item.Meter, payloads));
                Interlocked.Increment(ref _meters);
                Interlocked.Add(ref _messages, payloads.Length);
                return ValueTask.CompletedTask;
            });
            CheckReady();
            if (PreparedMessages == 0) throw new InvalidOperationException("Selected profiles produced no TCP payloads.");
            _prepared = prepared.ToArray();
            PreparedAtUtc = generated;
            PreparationTime = clock.Elapsed;
            Volatile.Write(ref _state, 2);
        }
        catch { _prepared = null; Volatile.Write(ref _state, 4); throw; }
    }

    public Task<TcpPushSummary> SendLiveAsync() => SendAsync(false);
    public Task<TcpPushSummary> FireAsync() => SendAsync(true);

    private async Task<TcpPushSummary> SendAsync(bool prepared)
    {
        if (Interlocked.CompareExchange(ref _state, 3, prepared ? 2 : 0) != (prepared ? 2 : 0))
            throw new InvalidOperationException("This run is not ready or has already been consumed.");
        try { return await SendPassAsync(prepared, _stop.Token); }
        finally { _prepared = null; Volatile.Write(ref _state, 4); }
    }

    public async Task<TcpLoopSummary> SendLoopAsync(TcpLoopOptions options)
    {
        options.Validate();
        if (Interlocked.CompareExchange(ref _state, 3, 0) != 0) throw new InvalidOperationException("This run has already been used.");
        using var duration = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
        if (options.DurationMinutes > 0) duration.CancelAfter(TimeSpan.FromMinutes(options.DurationMinutes));
        var clock = Stopwatch.StartNew();
        long cycles = 0;
        var totals = new TcpPushSummary(0, 0, 0, 0, 0, TimeSpan.Zero, null);
        try
        {
            while (true)
            {
                duration.Token.ThrowIfCancellationRequested();
                LastPass = null;
                TcpPushSummary pass;
                try { pass = await SendPassAsync(false, duration.Token); cycles++; }
                finally
                {
                    if (LastPass is { } done)
                        totals = new(totals.MetersSent + done.MetersSent, totals.MetersFailed + done.MetersFailed,
                            totals.MetersSkipped + done.MetersSkipped, totals.MessagesSent + done.MessagesSent,
                            totals.MessagesFailed + done.MessagesFailed, clock.Elapsed, totals.Error ?? done.Error);
                    LoopResult = new(cycles, totals with { SendTime = clock.Elapsed });
                }
                if (pass.MessagesSent == 0 && (pass.MetersFailed > 0 || pass.MetersSkipped == 0))
                    throw new InvalidOperationException(pass.Error ?? "No successful TCP writes. Loop stopped.");
                if (pass.MessagesSent == 0 && options.CyclePauseSeconds == 0) await Task.Delay(100, duration.Token);
                if (options.CyclePauseSeconds > 0) await Task.Delay(TimeSpan.FromSeconds(options.CyclePauseSeconds), duration.Token);
            }
        }
        catch (OperationCanceledException) when (duration.IsCancellationRequested && !_stop.IsCancellationRequested) { }
        finally { LoopResult = new(cycles, totals with { SendTime = clock.Elapsed }); Volatile.Write(ref _state, 4); }
        return LoopResult;
    }

    private async Task<TcpPushSummary> SendPassAsync(bool prepared, CancellationToken token)
    {
        long sent = 0, failed = 0, skipped = 0, messages = 0, rejected = 0;
        string? error = null;
        var clock = Stopwatch.StartNew();
        try
        {
            CheckReady();
            if (prepared && DateTimeOffset.UtcNow - PreparedAtUtc > TimeSpan.FromMinutes(5))
                throw new InvalidOperationException("Prepared payloads are older than five minutes. Prepare again.");
            IEnumerable<PreparedMeter> work = prepared ? _prepared! : Meters().Select(x => new PreparedMeter(x.Source, x.Meter, null));
            IEnumerable<IEnumerable<PreparedMeter>> waves = !prepared && _request.ChunkSize > 0 ? work.Chunk(_request.ChunkSize) : [work];
            bool first = true;
            foreach (var wave in waves)
            {
                if (!first && _request.ChunkIntervalSeconds > 0) await Task.Delay(TimeSpan.FromSeconds(_request.ChunkIntervalSeconds), token);
                first = false;
                await Parallel.ForEachAsync(wave, new ParallelOptions { MaxDegreeOfParallelism = _request.MaxConcurrency, CancellationToken = token }, async (item, ct) =>
                {
                    long started = Stopwatch.GetTimestamp();
                    try
                    {
                        ct.ThrowIfCancellationRequested();
                        byte[][] payloads = item.Payloads ?? item.Source.Build(item.Meter);
                        if (payloads.Length == 0) { Interlocked.Increment(ref skipped); _metrics?.RecordPushSkipped(NicType.Tcp4G); return; }
                        var result = await item.Source.Send(item.Meter, payloads, ct);
                        Interlocked.Add(ref messages, result.Sent);
                        Interlocked.Add(ref rejected, result.Failed);
                        _metrics?.RecordPushPayloads(NicType.Tcp4G, result.Sent, result.Failed);
                        _metrics?.RecordPushMeter(NicType.Tcp4G, result.Failed == 0, Stopwatch.GetElapsedTime(started));
                        if (result.Failed == 0) Interlocked.Increment(ref sent);
                        else { Interlocked.Increment(ref failed); Interlocked.CompareExchange(ref error, result.Error ?? "TCP connect/write failed.", null); }
                    }
                    catch (PushCanceledException ex)
                    {
                        Interlocked.Add(ref messages, ex.Sent);
                        Interlocked.Add(ref rejected, ex.Failed);
                        Interlocked.Increment(ref failed);
                        _metrics?.RecordPushPayloads(NicType.Tcp4G, ex.Sent, ex.Failed);
                        _metrics?.RecordPushMeter(NicType.Tcp4G, false, Stopwatch.GetElapsedTime(started));
                        throw;
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref failed);
                        _metrics?.RecordPushMeter(NicType.Tcp4G, false, Stopwatch.GetElapsedTime(started));
                        Interlocked.CompareExchange(ref error, ex.Message, null);
                    }
                });
            }
            return new(sent, failed, skipped, messages, rejected, clock.Elapsed, error);
        }
        finally { LastPass = new(sent, failed, skipped, messages, rejected, clock.Elapsed, error); }
    }

    private IEnumerable<(TcpPushSource Source, MeterRef Meter)> Meters()
    {
        var enumerators = _sources.Select(s => s.Meters().GetEnumerator()).ToArray();
        var finished = new bool[enumerators.Length];
        int remaining = enumerators.Length;
        try
        {
            while (remaining > 0)
                for (int i = 0; i < enumerators.Length; i++)
                {
                    _stop.Token.ThrowIfCancellationRequested();
                    if (finished[i]) continue;
                    if (enumerators[i].MoveNext()) yield return (_sources[i], enumerators[i].Current);
                    else { finished[i] = true; remaining--; }
                }
        }
        finally { foreach (var enumerator in enumerators) enumerator.Dispose(); }
    }

    public ValueTask DisposeAsync()
    {
        lock (_sync)
        {
            if (_disposed) return ValueTask.CompletedTask;
            _disposed = true;
            _unsubscribe(CheckConfiguration);
            _stop.Cancel();
            _stop.Dispose();
            _prepared = null;
            _batchLease?.Dispose();
        }
        return ValueTask.CompletedTask;
    }

    private sealed record PreparedMeter(TcpPushSource Source, MeterRef Meter, byte[][]? Payloads);
}
