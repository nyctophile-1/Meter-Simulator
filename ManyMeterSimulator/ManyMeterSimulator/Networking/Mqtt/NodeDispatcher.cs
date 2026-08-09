using System.Collections.Concurrent;
using System.Threading.Channels;
using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// Restores, for connectionless NICs, the two guarantees a TCP socket gave for free: exactly one
/// in-flight request per meter, handled in arrival order.
///
/// MQTT delivers every meter's traffic concurrently on one shared connection, so without this two
/// requests for the same meter could be handled simultaneously (corrupting DLMS association state)
/// or out of order (breaking block transfer). Each meter gets a bounded mailbox and a worker that
/// only exists while there is work — a dedicated task per meter would mean 100k parked tasks at
/// fleet scale.
///
/// A global semaphore bounds how many meters are inside the brain at once, so a poll storm becomes
/// queueing rather than thread-pool starvation.
/// </summary>
public sealed class NodeDispatcher
{
    private readonly ILogger _logger;
    private readonly Func<NicWorkItem, CancellationToken, Task> _process;
    private readonly SemaphoreSlim _concurrency;
    private readonly int _mailboxCapacity;
    private readonly ConcurrentDictionary<long, NodeMailbox> _mailboxes = new();

    public NodeDispatcher(
        ILogger logger,
        Func<NicWorkItem, CancellationToken, Task> process,
        int mailboxCapacity,
        int maxConcurrentBrainCalls)
    {
        _logger = logger;
        _process = process;
        _mailboxCapacity = Math.Max(1, mailboxCapacity);
        _concurrency = new SemaphoreSlim(Math.Max(1, maxConcurrentBrainCalls));
    }

    /// <summary>Messages queued across every meter, for shutdown draining and diagnostics.</summary>
    public int PendingCount => _mailboxes.Values.Sum(m => m.Count);

    /// <summary>
    /// Queues work for a meter and makes sure its worker is running.
    ///
    /// Returns false when that meter's mailbox is full — the caller records a drop. Dropping is
    /// deliberate: a real NIC under a request storm drops too, and queueing without bound would be
    /// an out-of-memory bug at fleet scale rather than back-pressure.
    /// </summary>
    public bool TryEnqueue(NicWorkItem item, CancellationToken cancellationToken)
    {
        NodeMailbox mailbox = _mailboxes.GetOrAdd(item.Meter.Index, _ => new NodeMailbox(_mailboxCapacity));

        if (!mailbox.TryWrite(item))
        {
            return false;
        }

        mailbox.EnsureDraining(this, cancellationToken);
        return true;
    }

    /// <summary>Waits until every mailbox is empty, or the timeout elapses. Used on shutdown.</summary>
    public async Task<bool> WaitForDrainAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow + timeout;
        while (PendingCount > 0 && DateTimeOffset.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(50, CancellationToken.None);
        }

        return PendingCount == 0;
    }

    private async Task DrainAsync(NodeMailbox mailbox, CancellationToken cancellationToken)
    {
        try
        {
            while (mailbox.TryRead(out NicWorkItem? item))
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return;
                }

                await _concurrency.WaitAsync(cancellationToken);
                try
                {
                    await _process(item!, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    // One meter's failure must never stop that meter's queue, let alone anyone else's.
                    _logger.LogError(ex, "Meter {Meter}: error processing message on {Topic}", item!.Meter, item.Envelope.Topic);
                }
                finally
                {
                    _concurrency.Release();
                }
            }
        }
        finally
        {
            mailbox.FinishDraining(this, cancellationToken);
        }
    }

    /// <summary>
    /// One meter's queue plus the flag that keeps exactly one worker on it.
    /// </summary>
    private sealed class NodeMailbox
    {
        private readonly Channel<NicWorkItem> _channel;
        private int _draining;

        public NodeMailbox(int capacity)
        {
            // Wait (not DropWrite) so a full mailbox makes TryWrite return false and the drop is
            // COUNTED. DropWrite would discard silently, which is the same behaviour with none of
            // the evidence.
            _channel = Channel.CreateBounded<NicWorkItem>(new BoundedChannelOptions(capacity)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait,
            });
        }

        public int Count => _channel.Reader.Count;

        public bool TryWrite(NicWorkItem item) => _channel.Writer.TryWrite(item);

        public bool TryRead(out NicWorkItem? item) => _channel.Reader.TryRead(out item);

        /// <summary>Starts a worker unless one is already running. No task exists while idle.</summary>
        public void EnsureDraining(NodeDispatcher dispatcher, CancellationToken cancellationToken)
        {
            if (Interlocked.CompareExchange(ref _draining, 1, 0) == 0)
            {
                _ = Task.Run(() => dispatcher.DrainAsync(this, cancellationToken), CancellationToken.None);
            }
        }

        /// <summary>
        /// Releases the worker slot, then re-checks. Without the re-check there is a lost-wakeup
        /// race: a writer that enqueued while the flag was still set skipped starting a worker, and
        /// its item would sit in the mailbox until the meter's next message — or forever.
        /// </summary>
        public void FinishDraining(NodeDispatcher dispatcher, CancellationToken cancellationToken)
        {
            Interlocked.Exchange(ref _draining, 0);

            if (_channel.Reader.Count > 0)
            {
                EnsureDraining(dispatcher, cancellationToken);
            }
        }
    }
}

/// <summary>
/// One unit of work: a routed message, ready for admission and the brain funnel.
///
/// <para>
/// <paramref name="Source"/> is what makes a multi-broker exchange correct. The reply must go back
/// on the connection the request arrived on — not on a client looked up by transport, which is
/// ambiguous the moment two brokers serve one — so the originating client travels with the work
/// item rather than being re-derived later (network_registry.md §5.2). The codec comes along for
/// the same reason: it belongs to that binding, and its fragment state must not be shared across
/// brokers.
/// </para>
/// </summary>
public sealed record NicWorkItem(
    MeterRef Meter,
    NicType Transport,
    INicCodec Codec,
    MqttNicOptions Options,
    NicEnvelope Envelope,
    NicRoute Route,
    BoundBrokerClient Source);
