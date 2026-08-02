using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.BadComm;

/// <summary>How the provisioned fleet splits across the three classes.</summary>
public readonly record struct FleetComposition(long Healthy, long BadComm, long NonComm)
{
    public long Total => Healthy + BadComm + NonComm;

    public double PercentOf(long count) => Total == 0 ? 0 : count * 100.0 / Total;
}

/// <summary>
/// Counts the fleet split by walking every provisioned meter index through the classifier.
///
/// That is O(fleet) - about a million hash evaluations - so it must never run on the dashboard's
/// 2-second refresh. Results are cached and only recomputed when the classifier generation or the
/// set of batches actually changes.
/// </summary>
public sealed class FleetCompositionCache
{
    private readonly MeterRegistry _registry;
    private readonly BadCommSettings _badComm;
    private readonly object _lock = new();

    private FleetComposition _cached;
    private int _cachedGeneration = -1;
    private long _cachedBatchFingerprint = -1;

    public FleetCompositionCache(MeterRegistry registry, BadCommSettings badComm)
    {
        _registry = registry;
        _badComm = badComm;
    }

    public FleetComposition Current()
    {
        MeterClassifier classifier = _badComm.Classifier;
        long fingerprint = BatchFingerprint();

        lock (_lock)
        {
            if (classifier.Generation == _cachedGeneration && fingerprint == _cachedBatchFingerprint)
            {
                return _cached;
            }

            _cached = Compute(classifier);
            _cachedGeneration = classifier.Generation;
            _cachedBatchFingerprint = fingerprint;
            return _cached;
        }
    }

    /// <summary>
    /// Counts against an arbitrary config without disturbing the cache, so the UI can preview a
    /// change before it is applied.
    /// </summary>
    public FleetComposition Preview(BadCommConfig config) => Compute(new MeterClassifier(config, -1));

    private FleetComposition Compute(MeterClassifier classifier)
    {
        long healthy = 0, bad = 0, non = 0;

        foreach (MeterBatch batch in _registry.Batches)
        {
            for (long i = batch.StartIndex; i <= batch.EndIndex; i++)
            {
                switch (classifier.Classify(i).Class)
                {
                    case CommClass.NonComm: non++; break;
                    case CommClass.BadComm: bad++; break;
                    default: healthy++; break;
                }
            }
        }

        return new FleetComposition(healthy, bad, non);
    }

    /// <summary>Cheap stand-in for "have the batches changed" - count, ranges and ids folded together.</summary>
    private long BatchFingerprint()
    {
        long fingerprint = 17;
        foreach (MeterBatch b in _registry.Batches)
        {
            fingerprint = fingerprint * 31 + b.Id;
            fingerprint = fingerprint * 31 + b.StartIndex;
            fingerprint = fingerprint * 31 + b.Count;
        }

        return fingerprint;
    }
}
