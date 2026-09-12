using System.Collections.Concurrent;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.ProfileSimulation;

/// <summary>
/// Advances explicitly configured profile buffers. It generates only completed capture intervals,
/// persists the working XML before reporting a capture, and performs no network delivery. Delivery
/// is deliberately separate because the current sender cannot encode an exact saved DP/billing/event
/// record without a verified mapping from profile record to HES push layout.
/// </summary>
public sealed class ProfileSimulationService
{
    private readonly MeterRegistry _registry;
    private readonly MeterSessionManager _sessions;
    private readonly ProfileSimulationOptions _options;
    private readonly TimeZoneInfo _timeZone;
    private readonly ILogger<ProfileSimulationService> _logger;
    private readonly ConcurrentDictionary<int, long> _nextBatchIndex = new();

    public ProfileSimulationService(
        MeterRegistry registry,
        MeterSessionManager sessions,
        IOptions<ProfileSimulationOptions> options,
        ILogger<ProfileSimulationService> logger)
    {
        _registry = registry;
        _sessions = sessions;
        _options = options.Value;
        _logger = logger;
        _timeZone = ResolveTimeZone(_options);
        ValidateOptions(_options);
    }

    public bool Enabled => _options.Enabled && _options.Profiles.Count > 0;

    /// <summary>
    /// Advances a single meter through due, configured profile captures. It is idempotent for a
    /// repeated clock value because each next boundary is strictly after the latest saved capture.
    /// </summary>
    public ProfileAdvanceResult AdvanceMeter(MeterRef meter, DateTimeOffset nowUtc)
    {
        if (!Enabled)
        {
            return ProfileAdvanceResult.Disabled(meter);
        }

        MeterBatch? batch = _registry.GetBatchForIndex(meter.Index);
        if (batch is null)
        {
            return ProfileAdvanceResult.NotAdvanced(meter, "Meter belongs to no batch.");
        }

        DLMSServerSession session = _sessions.GetOrCreate(meter);
        var captured = new List<ProfileCaptureResult>();
        var skipped = new List<string>();

        lock (session)
        {
            IReadOnlyDictionary<string, ProfileBufferState> states = session.GetProfileBufferStates()
                .ToDictionary(state => state.LogicalName, StringComparer.Ordinal);

            foreach (ProfileSimulationProfile configured in _options.Profiles)
            {
                if (!states.TryGetValue(configured.LogicalName, out ProfileBufferState state))
                {
                    skipped.Add($"{configured.LogicalName}: not present in template");
                    continue;
                }

                if (state.LatestCaptureAtUtc is null)
                {
                    skipped.Add($"{configured.LogicalName}: no timestamped seed record");
                    continue;
                }

                int periodSeconds = configured.CapturePeriodSeconds > 0
                    ? configured.CapturePeriodSeconds
                    : checked((int)state.CapturePeriodSeconds);
                if (periodSeconds <= 0)
                {
                    skipped.Add($"{configured.LogicalName}: no configured capture period");
                    continue;
                }

                DateTimeOffset lastCompletedBoundary = CompletedBoundary(nowUtc, periodSeconds);
                DateTimeOffset next = NextBoundaryAfter(state.LatestCaptureAtUtc.Value, periodSeconds);
                IReadOnlyDictionary<string, decimal> increments = configured.ValueIncrements
                    .ToDictionary(value => value.CaptureObjectLogicalName, value => value.IncrementPerCapture, StringComparer.Ordinal);

                int generatedForProfile = 0;
                while (next <= lastCompletedBoundary && generatedForProfile < _options.MaxCapturesPerMeterPerCycle)
                {
                    captured.Add(session.AppendProfileCapture(configured.LogicalName, next, increments));
                    generatedForProfile++;
                    next = NextBoundaryAfter(next, periodSeconds);
                }

                if (next <= lastCompletedBoundary)
                {
                    skipped.Add($"{configured.LogicalName}: catch-up limit {_options.MaxCapturesPerMeterPerCycle} reached");
                }
            }

            // The working XML becomes durable before this method exposes newly generated records to
            // the scheduler. A failed save throws, leaving the caller with no false success result.
            if (captured.Count > 0)
            {
                _sessions.SaveProfileWorkingState(meter, session);
            }
        }

        if (captured.Count > 0)
        {
            _logger.LogInformation(
                "Generated {Count} profile capture(s) for meter {Meter} through {NowUtc:u}",
                captured.Count, meter, nowUtc);
        }

        return new ProfileAdvanceResult(meter, captured, skipped, false, null);
    }

    /// <summary>
    /// Advances a bounded round-robin slice of every running batch. This bounds CPU, XML writes,
    /// and filesystem pressure even when a batch contains lakhs of meters.
    /// </summary>
    public IReadOnlyList<ProfileAdvanceResult> AdvanceRunningBatches(DateTimeOffset nowUtc)
    {
        if (!Enabled)
        {
            return Array.Empty<ProfileAdvanceResult>();
        }

        var results = new List<ProfileAdvanceResult>();
        foreach (MeterBatch batch in _registry.Batches.Where(batch => batch.Status == BatchStatus.Running))
        {
            long start = _nextBatchIndex.GetOrAdd(batch.Id, batch.StartIndex);
            if (start < batch.StartIndex || start > batch.EndIndex)
            {
                start = batch.StartIndex;
            }

            int processed = 0;
            long index = start;
            while (processed < _options.MaxMetersPerBatchPerCycle && processed < batch.Count)
            {
                results.Add(AdvanceMeter(new MeterRef(index, batch.NicType), nowUtc));
                processed++;
                index = index == batch.EndIndex ? batch.StartIndex : index + 1;
            }

            _nextBatchIndex[batch.Id] = index;
        }

        return results;
    }

    private DateTimeOffset CompletedBoundary(DateTimeOffset nowUtc, int periodSeconds)
    {
        DateTimeOffset local = TimeZoneInfo.ConvertTime(nowUtc, _timeZone);
        var dayStart = new DateTimeOffset(local.Year, local.Month, local.Day, 0, 0, 0, local.Offset);
        long elapsedSeconds = (long)Math.Floor((local - dayStart).TotalSeconds);
        return dayStart.AddSeconds(elapsedSeconds / periodSeconds * periodSeconds).ToUniversalTime();
    }

    private DateTimeOffset NextBoundaryAfter(DateTimeOffset timestampUtc, int periodSeconds)
    {
        DateTimeOffset local = TimeZoneInfo.ConvertTime(timestampUtc, _timeZone);
        var dayStart = new DateTimeOffset(local.Year, local.Month, local.Day, 0, 0, 0, local.Offset);
        long elapsedSeconds = (long)Math.Floor((local - dayStart).TotalSeconds);
        return dayStart.AddSeconds((elapsedSeconds / periodSeconds + 1) * periodSeconds).ToUniversalTime();
    }

    private static TimeZoneInfo ResolveTimeZone(ProfileSimulationOptions options)
    {
        try
        {
            TimeZoneInfo timeZone = TimeZoneInfo.FindSystemTimeZoneById(options.TimeZoneId);
            if (options.Enabled && timeZone.SupportsDaylightSavingTime)
            {
                throw new InvalidOperationException(
                    $"ProfileSimulation timezone '{options.TimeZoneId}' observes daylight saving time. " +
                    "DST capture-boundary semantics must be configured before simulation can be enabled.");
            }

            return timeZone;
        }
        catch (TimeZoneNotFoundException exception)
        {
            throw new InvalidOperationException($"ProfileSimulation timezone '{options.TimeZoneId}' is not available on this host.", exception);
        }
    }

    private static void ValidateOptions(ProfileSimulationOptions options)
    {
        if (!options.Enabled)
        {
            return;
        }

        if (options.SchedulerIntervalSeconds is < 1 or > 3600)
        {
            throw new InvalidOperationException("ProfileSimulation:SchedulerIntervalSeconds must be between 1 and 3600.");
        }

        if (options.MaxMetersPerBatchPerCycle is < 1 or > 100_000)
        {
            throw new InvalidOperationException("ProfileSimulation:MaxMetersPerBatchPerCycle must be between 1 and 100000.");
        }

        if (options.MaxCapturesPerMeterPerCycle is < 1 or > 10_000)
        {
            throw new InvalidOperationException("ProfileSimulation:MaxCapturesPerMeterPerCycle must be between 1 and 10000.");
        }

        foreach (IGrouping<string, ProfileSimulationProfile> duplicate in options.Profiles.GroupBy(profile => profile.LogicalName, StringComparer.Ordinal))
        {
            if (string.IsNullOrWhiteSpace(duplicate.Key) || duplicate.Count() != 1)
            {
                throw new InvalidOperationException("ProfileSimulation profile logical names must be non-empty and unique.");
            }

            ProfileSimulationProfile profile = duplicate.Single();
            if (profile.CapturePeriodSeconds < 0)
            {
                throw new InvalidOperationException($"ProfileSimulation capture period for '{profile.LogicalName}' cannot be negative.");
            }

            if (profile.ValueIncrements.Any(value => string.IsNullOrWhiteSpace(value.CaptureObjectLogicalName))
                || profile.ValueIncrements.GroupBy(value => value.CaptureObjectLogicalName, StringComparer.Ordinal).Any(group => group.Count() != 1))
            {
                throw new InvalidOperationException(
                    $"ProfileSimulation increments for '{profile.LogicalName}' must have non-empty, unique capture-object logical names.");
            }
        }
    }
}

/// <summary>One read-only result from a meter advancement attempt.</summary>
public sealed record ProfileAdvanceResult(
    MeterRef Meter,
    IReadOnlyList<ProfileCaptureResult> Captures,
    IReadOnlyList<string> Skipped,
    bool IsDisabled,
    string? Error)
{
    public static ProfileAdvanceResult Disabled(MeterRef meter) =>
        new(meter, Array.Empty<ProfileCaptureResult>(), Array.Empty<string>(), true, null);

    public static ProfileAdvanceResult NotAdvanced(MeterRef meter, string reason) =>
        new(meter, Array.Empty<ProfileCaptureResult>(), [reason], false, null);
}
