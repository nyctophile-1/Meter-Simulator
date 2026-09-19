namespace ManyMeterSimulator.Brain;

// Only meters awaiting restoration occupy persistent space; gates exist only while in use.
internal sealed class PowerEventSequence
{
    private readonly object _sync = new();
    private readonly HashSet<long> _restoration = [];
    private readonly Dictionary<long, Gate> _gates = [];

    public ushort Next(long meter)
    {
        lock (_sync) return (ushort)(_restoration.Contains(meter) ? 102 : 101);
    }

    public void Confirm(long meter, ushort eventId)
    {
        lock (_sync)
        {
            if (Next(meter) != eventId) throw new InvalidOperationException("Power-event sequence changed during delivery.");
            if (eventId == 101) _restoration.Add(meter);
            else _restoration.Remove(meter);
        }
    }

    public async ValueTask<IDisposable> AcquireAsync(long meter, CancellationToken token)
    {
        Gate gate;
        lock (_sync)
        {
            if (!_gates.TryGetValue(meter, out gate!)) _gates[meter] = gate = new();
            gate.Users++;
        }
        try { await gate.Semaphore.WaitAsync(token); }
        catch { Release(meter, gate, false); throw; }
        return new Lease(() => Release(meter, gate, true));
    }

    private void Release(long meter, Gate gate, bool acquired)
    {
        lock (_sync)
        {
            if (acquired) gate.Semaphore.Release();
            if (--gate.Users == 0) { _gates.Remove(meter); gate.Semaphore.Dispose(); }
        }
    }

    private sealed class Gate
    {
        public readonly SemaphoreSlim Semaphore = new(1, 1);
        public int Users;
    }

    private sealed class Lease(Action release) : IDisposable
    {
        private Action? _release = release;
        public void Dispose() => Interlocked.Exchange(ref _release, null)?.Invoke();
    }
}
