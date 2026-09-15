using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;

namespace ManyMeterSimulator.Tests;

public class TcpPushRunTests
{
    private static TcpPushRun Run(int count, Func<MeterRef, byte[][]> build,
        Func<MeterRef, byte[][], CancellationToken, Task<PushDeliveryResult>> send,
        TcpPushRequest? request = null, CancellationToken token = default, bool ciphering = false,
        Func<bool>? current = null, Action<Action>? subscribe = null) =>
        new([new TcpPushSource(count, () => Enumerable.Range(1, count).Select(i => new MeterRef(i, NicType.Tcp4G)),
            build, send, current ?? (() => true))], request ?? new() { BatchIds = [1], MaxConcurrency = 1 }, ciphering,
            token, subscribe ?? (_ => { }), _ => { });

    [Fact]
    public async Task PrepareDoesNotSend_AndFireUsesThePreparedBytesOnlyOnce()
    {
        int built = 0, sent = 0;
        await using var run = Run(3, _ => [new byte[] { (byte)++built }], (_, bytes, _) =>
        {
            Assert.InRange(bytes[0][0], (byte)1, (byte)3);
            sent++;
            return Task.FromResult(new PushDeliveryResult(1, 0));
        });
        await run.PrepareAsync();
        Assert.Equal(3, built);
        Assert.Equal(0, sent);
        Assert.Equal(3, run.PreparedMessages);
        var result = await run.FireAsync();
        Assert.Equal(3, result.MessagesSent);
        Assert.Equal(3, built);
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.FireAsync());
    }

    [Fact]
    public async Task LivePassKeepsOnlyConfiguredWorkersInFlight()
    {
        const int concurrency = 256;
        int built = 0;
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await using var run = Run(1000, _ => { if (Interlocked.Increment(ref built) == concurrency) ready.SetResult(); return [[1]]; },
            async (_, _, ct) => { await release.Task.WaitAsync(ct); return new(1, 0); },
            new() { BatchIds = [1], MaxConcurrency = concurrency }, stop.Token);
        var sending = run.SendLiveAsync();
        await ready.Task.WaitAsync(stop.Token);
        Assert.Equal(concurrency, built);
        release.SetResult();
        Assert.Equal(1000, (await sending).MetersSent);
    }

    [Fact]
    public async Task LoopRegeneratesPayloadsAndRetainsInterruptedPassTotals()
    {
        int built = 0, sent = 0;
        using var stop = new CancellationTokenSource();
        await using var run = Run(3, _ => [new byte[] { (byte)++built }], (_, _, _) =>
        {
            if (++sent == 7) stop.Cancel();
            return Task.FromResult(new PushDeliveryResult(1, 0));
        }, token: stop.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.SendLoopAsync(new()));
        Assert.Equal(7, built);
        Assert.Equal(2, run.LoopResult!.CompletedCycles);
        Assert.Equal(7, run.LoopResult.Totals.MessagesSent);
    }

    [Fact]
    public async Task ChangedBatchCancelsReadyDataBeforeItCanBeSent()
    {
        bool current = true;
        Action? changed = null;
        await using var run = Run(1, _ => [[1]], (_, _, _) => throw new Exception("Must not send"),
            current: () => current, subscribe: h => changed = h);
        await run.PrepareAsync();
        current = false;
        changed!();
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.FireAsync());
    }

    [Fact]
    public async Task CipheredPreparationAndOversizedDatasetsAreRejected()
    {
        await using var ciphered = Run(1, _ => throw new Exception("Must not encode"), (_, _, _) => throw new Exception(), ciphering: true);
        await Assert.ThrowsAsync<InvalidOperationException>(() => ciphered.PrepareAsync());
        await using var oversized = Run(1, _ => [new byte[1024 * 1024]], (_, _, _) => throw new Exception(),
            new() { BatchIds = [1], PreparedMemoryMiB = 1 });
        await Assert.ThrowsAsync<InvalidOperationException>(() => oversized.PrepareAsync());
    }

    [Fact]
    public async Task AllFailedPassStopsContinuousRunWithoutRetrying()
    {
        int attempts = 0;
        await using var run = Run(3, _ => [[1]], (_, _, _) => { attempts++; return Task.FromResult(new PushDeliveryResult(0, 1)); });
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.SendLoopAsync(new()));
        Assert.Equal(3, attempts);
        Assert.Equal(3, run.LoopResult!.Totals.MessagesFailed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1025)]
    public void InvalidConcurrencyIsRejected(int concurrency) =>
        Assert.Throws<ArgumentException>(() => new TcpPushRequest { BatchIds = [1], MaxConcurrency = concurrency }.Validate());
}
