using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;

namespace ManyMeterSimulator.Tests;

public class HistoricalUnlimitedTests
{
    [Fact]
    public async Task UnlimitedTimestampExceedsOldCapsAndResumesLargeCompletionHoles()
    {
        const int count = 4097;
        int completed = 0;
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var time = new DateTimeOffset(2026, 9, 21, 0, 0, 0, TimeSpan.Zero);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var source = new HistoricalPushSource(1, 1, count, NicType.Tcp4G, "0.0.25.9.0.255", 900,
            () => true, async (meter, _, ct) =>
            {
                if (meter.Index == 1)
                {
                    await Task.Delay(Timeout.Infinite, ct);
                }

                if (Interlocked.Increment(ref completed) == count - 1)
                {
                    ready.TrySetResult();
                }

                return new PushDeliveryResult(1, 0);
            });
        var request = new HistoricalPushRequest { BatchIds = [1] };
        await using var run = new HistoricalPushRun([source], [], request, time, time,
            (_, _) => Task.FromResult(true), new SimulatorMetrics());
        HistoricalPushCheckpoint? saved = null;
        var sending = run.SendAsync(_ => { }, stop.Token, checkpoint => saved = checkpoint);
        await ready.Task.WaitAsync(stop.Token);
        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending);

        Assert.NotNull(saved);
        Assert.Equal(count - 1, saved.Progress.Sent);
        Assert.Equal(count - 1, saved.Sources[0].CompletedAhead.Length);
        Assert.Equal(0, saved.Sources[0].NextRecord);
        int resumed = 0;
        var resumedSource = source with
        {
            Send = (meter, _, _) =>
            {
                Assert.Equal(1, meter.Index);
                Interlocked.Increment(ref resumed);
                return Task.FromResult(new PushDeliveryResult(1, 0));
            }
        };
        await using var continuation = new HistoricalPushRun([resumedSource], [], request, time, time,
            (_, _) => Task.FromResult(true), new SimulatorMetrics(), saved);
        var result = await continuation.SendAsync(_ => { }, default);

        Assert.Equal(1, resumed);
        Assert.Equal(count, result.Sent);
        Assert.Equal(0, result.Failed);
    }
}
