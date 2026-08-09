using System.Collections.Concurrent;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Mqtt.Codecs;
using ManyMeterSimulator.Networking.Nic;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// The dispatcher restores what a TCP socket gave for free: one in-flight request per meter, in
/// arrival order. Those two properties are the whole reason it exists, so they are tested directly
/// rather than inferred from an end-to-end run.
/// </summary>
public class NodeDispatcherTests
{
    private static readonly INicCodec Codec = new Mqtt4GCodec(NicType.Mqtt4G);

    /// <summary>
    /// A work item's source binding — where its reply would be published. Constructing the client
    /// opens no socket, so this is inert here; the dispatcher only carries the reference through.
    /// </summary>
    private static readonly BoundBrokerClient Source = new(
        new BrokerBinding(NicType.Mqtt4G, "test-broker"),
        new BrokerEndpoint { Key = "test-broker", Host = "localhost" },
        new MqttNicClient(NullLogger.Instance, NicType.Mqtt4G, new MqttBrokerOptions(), _ => Task.CompletedTask),
        Codec,
        new MqttNicOptions(),
        new CancellationTokenSource());

    private static NicWorkItem Item(long index, string tag) =>
        new(new MeterRef(index, NicType.Mqtt4G),
            NicType.Mqtt4G,
            Codec,
            new MqttNicOptions(),
            new NicEnvelope($"PollRequest/{index}", System.Text.Encoding.UTF8.GetBytes(tag), DateTimeOffset.UtcNow),
            new NicRoute(index.ToString()),
            Source);

    private static NodeDispatcher Dispatcher(
        Func<NicWorkItem, CancellationToken, Task> process,
        int mailboxCapacity = 32,
        int maxConcurrent = 8) =>
        new(NullLogger.Instance, process, mailboxCapacity, maxConcurrent);

    private static async Task<bool> WaitUntilAsync(Func<bool> condition, int timeoutMs = 5000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(10);
        }

        return condition();
    }

    [Fact]
    public async Task ProcessesOneMetersMessagesInArrivalOrder()
    {
        var seen = new List<string>();
        NodeDispatcher dispatcher = Dispatcher(async (item, _) =>
        {
            // A little work per item, so an out-of-order implementation would actually show it.
            await Task.Delay(5);
            lock (seen)
            {
                seen.Add(System.Text.Encoding.UTF8.GetString(item.Envelope.Payload));
            }
        });

        for (int i = 0; i < 25; i++)
        {
            Assert.True(dispatcher.TryEnqueue(Item(1, $"msg{i:D2}"), CancellationToken.None));
        }

        Assert.True(await WaitUntilAsync(() => seen.Count == 25));
        Assert.Equal(Enumerable.Range(0, 25).Select(i => $"msg{i:D2}"), seen);
    }

    [Fact]
    public async Task NeverRunsTwoMessagesForTheSameMeterConcurrently()
    {
        int concurrent = 0;
        int maxObserved = 0;

        NodeDispatcher dispatcher = Dispatcher(async (_, _) =>
        {
            int now = Interlocked.Increment(ref concurrent);
            InterlockedMax(ref maxObserved, now);
            await Task.Delay(5);
            Interlocked.Decrement(ref concurrent);
        });

        for (int i = 0; i < 20; i++)
        {
            dispatcher.TryEnqueue(Item(7, $"m{i}"), CancellationToken.None);
        }

        Assert.True(await WaitUntilAsync(() => dispatcher.PendingCount == 0 && Volatile.Read(ref concurrent) == 0));
        Assert.Equal(1, maxObserved);   // a DLMS session is not thread-safe — this must never exceed 1
    }

    [Fact]
    public async Task DifferentMetersAreProcessedConcurrently()
    {
        var started = new CountdownEvent(4);
        var release = new TaskCompletionSource();

        NodeDispatcher dispatcher = Dispatcher(async (_, _) =>
        {
            started.Signal();
            await release.Task;
        });

        for (long meter = 1; meter <= 4; meter++)
        {
            dispatcher.TryEnqueue(Item(meter, "x"), CancellationToken.None);
        }

        // All four must be in flight at once; if meters were serialized this would time out.
        Assert.True(await WaitUntilAsync(() => started.CurrentCount == 0));
        release.SetResult();
    }

    [Fact]
    public async Task DropsWhenAMetersMailboxIsFull_AndKeepsServingOtherMeters()
    {
        var release = new TaskCompletionSource();
        var processed = new ConcurrentBag<long>();

        NodeDispatcher dispatcher = Dispatcher(
            async (item, _) =>
            {
                await release.Task;
                processed.Add(item.Meter.Index);
            },
            mailboxCapacity: 2);

        // One item goes to the worker (which blocks), then 2 fill the mailbox, so the 4th is dropped.
        Assert.True(dispatcher.TryEnqueue(Item(1, "a"), CancellationToken.None));
        Assert.True(await WaitUntilAsync(() => dispatcher.PendingCount == 0));   // "a" is in the handler

        Assert.True(dispatcher.TryEnqueue(Item(1, "b"), CancellationToken.None));
        Assert.True(dispatcher.TryEnqueue(Item(1, "c"), CancellationToken.None));
        Assert.False(dispatcher.TryEnqueue(Item(1, "d"), CancellationToken.None));   // full → dropped

        // A different meter is unaffected — one meter's back-pressure must not become the fleet's.
        Assert.True(dispatcher.TryEnqueue(Item(2, "a"), CancellationToken.None));

        release.SetResult();
        Assert.True(await WaitUntilAsync(() => processed.Count == 4));
        Assert.Equal(3, processed.Count(i => i == 1));
        Assert.Equal(1, processed.Count(i => i == 2));
    }

    /// <summary>
    /// The lost-wakeup race: an item enqueued in the instant a worker is finishing must still be
    /// picked up. Without the re-check in FinishDraining it would sit in the mailbox until the
    /// meter's next message — or forever, if that was the last one.
    /// </summary>
    [Fact]
    public async Task DoesNotLoseAnItemEnqueuedWhileAWorkerIsFinishing()
    {
        int processed = 0;
        NodeDispatcher dispatcher = Dispatcher((_, _) =>
        {
            Interlocked.Increment(ref processed);
            return Task.CompletedTask;
        });

        // Hammer a single meter from several threads so enqueues land at every point in the
        // worker's lifecycle, including the drain/finish boundary.
        const int total = 2000;
        await Task.WhenAll(Enumerable.Range(0, 4).Select(t => Task.Run(() =>
        {
            for (int i = 0; i < total / 4; i++)
            {
                while (!dispatcher.TryEnqueue(Item(1, $"t{t}-{i}"), CancellationToken.None))
                {
                    Thread.SpinWait(50);   // mailbox full: retry rather than count this as a drop
                }
            }
        })));

        Assert.True(await WaitUntilAsync(() => Volatile.Read(ref processed) == total, timeoutMs: 20000));
        Assert.Equal(total, Volatile.Read(ref processed));
        Assert.Equal(0, dispatcher.PendingCount);
    }

    [Fact]
    public async Task AHandlerThrowing_DoesNotStopTheQueue()
    {
        int processed = 0;
        NodeDispatcher dispatcher = Dispatcher((item, _) =>
        {
            Interlocked.Increment(ref processed);
            if (System.Text.Encoding.UTF8.GetString(item.Envelope.Payload) == "boom")
            {
                throw new InvalidOperationException("codec blew up");
            }

            return Task.CompletedTask;
        });

        dispatcher.TryEnqueue(Item(1, "ok1"), CancellationToken.None);
        dispatcher.TryEnqueue(Item(1, "boom"), CancellationToken.None);
        dispatcher.TryEnqueue(Item(1, "ok2"), CancellationToken.None);

        Assert.True(await WaitUntilAsync(() => Volatile.Read(ref processed) == 3));
        Assert.Equal(0, dispatcher.PendingCount);
    }

    [Fact]
    public async Task WaitForDrain_ReportsWhetherEverythingFinished()
    {
        var release = new TaskCompletionSource();
        NodeDispatcher dispatcher = Dispatcher(async (_, _) => await release.Task);

        dispatcher.TryEnqueue(Item(1, "a"), CancellationToken.None);
        dispatcher.TryEnqueue(Item(1, "b"), CancellationToken.None);

        Assert.False(await dispatcher.WaitForDrainAsync(TimeSpan.FromMilliseconds(200), CancellationToken.None));

        release.SetResult();
        Assert.True(await dispatcher.WaitForDrainAsync(TimeSpan.FromSeconds(5), CancellationToken.None));
    }

    private static void InterlockedMax(ref int location, int value)
    {
        int current;
        do
        {
            current = Volatile.Read(ref location);
            if (value <= current)
            {
                return;
            }
        }
        while (Interlocked.CompareExchange(ref location, value, current) != current);
    }
}
