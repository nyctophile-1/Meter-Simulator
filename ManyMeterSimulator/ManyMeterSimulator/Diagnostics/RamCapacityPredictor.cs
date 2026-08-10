using System.Diagnostics;

namespace ManyMeterSimulator.Diagnostics;

public record RamCapacityPrediction(
    long FreeRamBytes,
    double FreeRamMb,
    double AvgBytesPerMeter,
    double AvgKbPerMeter,
    long PredictedMaxAdditionalMeters,
    long PredictedMaxTotalMeters)
{
    public double CurrentUsagePercent(long currentMeters) =>
        PredictedMaxTotalMeters > 0 ? Math.Clamp(currentMeters * 100.0 / PredictedMaxTotalMeters, 0, 100) : 0;
}

public static class RamCapacityPredictor
{
    public const long SystemBufferBytes = 1024L * 1024L * 1024L; // 1 GB reserved for OS & host system overhead
    public const double BaselineBytesPerMeter = 3500.0; // 3.5 KB baseline per session when no live meters exist yet

    public static RamCapacityPrediction Predict(long currentWorkingSetBytes, int activeMeterCount)
    {
        long totalRam = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        long freeRamBytes = Math.Max(0, totalRam - currentWorkingSetBytes - SystemBufferBytes);

        double avgBytesPerMeter = activeMeterCount > 0
            ? Math.Max(1000.0, (double)currentWorkingSetBytes / activeMeterCount)
            : BaselineBytesPerMeter;

        long additionalMeters = (long)(freeRamBytes / avgBytesPerMeter);
        long maxTotalMeters = activeMeterCount + additionalMeters;

        return new RamCapacityPrediction(
            FreeRamBytes: freeRamBytes,
            FreeRamMb: freeRamBytes / 1024.0 / 1024.0,
            AvgBytesPerMeter: avgBytesPerMeter,
            AvgKbPerMeter: avgBytesPerMeter / 1024.0,
            PredictedMaxAdditionalMeters: additionalMeters,
            PredictedMaxTotalMeters: maxTotalMeters);
    }

    public static RamCapacityPrediction PredictCurrentProcess(int activeMeterCount)
    {
        using Process proc = Process.GetCurrentProcess();
        return Predict(proc.WorkingSet64, activeMeterCount);
    }
}
