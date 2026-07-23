using System.Net;

namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// Tracks meter batches - the real provisioning unit. Each batch reserves a contiguous run of
/// 1-based indices; a meter's IP address and meter serial number are both deterministic
/// functions of its index within the range (see MeterAddressing/FormatSerial), so batches never
/// overlap and each new batch simply continues from wherever the previous one left off.
///
/// Purely app-layer bookkeeping - doesn't touch OS-level routing/address assignment, which is a
/// separate, environment-specific setup step done outside the app.
/// </summary>
public sealed class MeterRegistry
{
    /// <summary>Meter serial numbers are "MY" + 9 zero-padded digits, so this is the largest supported index (one shy of a billion).</summary>
    public const long MaxIndex = 999_999_999;

    private readonly List<MeterBatch> _batches = new();
    private readonly object _lock = new();
    private long _nextIndex = 1;
    private int _nextBatchId = 1;

    public IReadOnlyList<MeterBatch> Batches
    {
        get
        {
            lock (_lock)
            {
                return _batches.ToArray();
            }
        }
    }

    /// <summary>What the next batch of the given size would reserve, without reserving anything yet.</summary>
    public BatchPreview PreviewNextBatch(string addressPrefixCidr, long count)
    {
        lock (_lock)
        {
            long start = _nextIndex;
            long end = start + count - 1;
            return new BatchPreview(
                MeterAddressing.ComputeAddress(addressPrefixCidr, start),
                MeterAddressing.ComputeAddress(addressPrefixCidr, end),
                FormatSerial(start),
                FormatSerial(end));
        }
    }

    /// <summary>
    /// Reserves the next `count` indices as a new batch bound to <paramref name="templateName"/>.
    /// Does not start it. Every meter in the batch is built from that template.
    /// </summary>
    public MeterBatch AddBatch(string name, string templateName, long count)
    {
        if (count <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "Must provision at least one meter.");
        }

        if (string.IsNullOrWhiteSpace(templateName))
        {
            throw new ArgumentException("A batch must be bound to a template.", nameof(templateName));
        }

        lock (_lock)
        {
            if (_nextIndex + count - 1 > MaxIndex)
            {
                long remaining = MaxIndex - _nextIndex + 1;
                throw new InvalidOperationException(
                    $"Cannot add {count} meter(s): only {remaining} remain before the {MaxIndex} max is reached.");
            }

            var batch = new MeterBatch
            {
                Id = _nextBatchId++,
                Name = name,
                TemplateName = templateName,
                StartIndex = _nextIndex,
                Count = count
            };
            _batches.Add(batch);
            _nextIndex += count;
            return batch;
        }
    }

    public bool TryStart(int batchId) => TrySetStatus(batchId, BatchStatus.Running);

    public bool TryStop(int batchId) => TrySetStatus(batchId, BatchStatus.Stopped);

    public bool Delete(int batchId)
    {
        lock (_lock)
        {
            return _batches.RemoveAll(b => b.Id == batchId) > 0;
        }
    }

    /// <summary>The IP address, meter serial for every index in a batch. Lazy - caller controls how many are enumerated/rendered.</summary>
    public IEnumerable<(long Index, IPAddress Address, string Serial)> GetMeters(MeterBatch batch, string addressPrefixCidr)
    {
        for (long i = batch.StartIndex; i <= batch.EndIndex; i++)
        {
            yield return (i, MeterAddressing.ComputeAddress(addressPrefixCidr, i), FormatSerial(i));
        }
    }

    /// <summary>First/last address of a batch's own range - O(1), doesn't enumerate the whole batch.</summary>
    public (IPAddress First, IPAddress Last) GetAddressRange(MeterBatch batch, string addressPrefixCidr) =>
        (MeterAddressing.ComputeAddress(addressPrefixCidr, batch.StartIndex),
         MeterAddressing.ComputeAddress(addressPrefixCidr, batch.EndIndex));

    /// <summary>The batch that owns this address, or null if the address isn't part of any batch.</summary>
    public MeterBatch? GetBatchForAddress(IPAddress address)
    {
        long index = MeterAddressing.ExtractIndex(address);

        lock (_lock)
        {
            foreach (MeterBatch batch in _batches)
            {
                if (index >= batch.StartIndex && index <= batch.EndIndex)
                {
                    return batch;
                }
            }
        }

        return null;
    }

    /// <summary>Status of the batch that owns this address, or null if the address isn't part of any batch.</summary>
    public BatchStatus? GetBatchStatusForAddress(IPAddress address, string addressPrefixCidr) =>
        GetBatchForAddress(address)?.Status;

    /// <summary>Template name of the batch that owns this address, or null if unprovisioned.</summary>
    public string? GetTemplateNameForAddress(IPAddress address) =>
        GetBatchForAddress(address)?.TemplateName;

    private bool TrySetStatus(int batchId, BatchStatus status)
    {
        lock (_lock)
        {
            MeterBatch? batch = _batches.FirstOrDefault(b => b.Id == batchId);
            if (batch is null)
            {
                return false;
            }

            batch.Status = status;
            return true;
        }
    }

    public static string FormatSerial(long index) => $"MY{index:D9}";
}

public readonly record struct BatchPreview(IPAddress FirstAddress, IPAddress LastAddress, string FirstSerial, string LastSerial);
