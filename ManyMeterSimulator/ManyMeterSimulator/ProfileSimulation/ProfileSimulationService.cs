using System.Collections.Concurrent;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.Models;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.ProfileSimulation;

/// <summary>
/// Advances explicitly configured profiles for a BATCH, not a meter — every meter in a batch
/// generates byte-identical simulated data (config-driven increments applied at the same
/// boundaries), so there is exactly one timeline of generated data per batch, held in
/// <see cref="BatchProfileSimulationState"/> and persisted as one shared working XML (see
/// <see cref="ProfileSimulationStateStore"/>). It saves the working state after each generating
/// pass and, per profile, either queues an automatic push or leaves delivery to the operator's
/// manual "Send Push Now" action.
/// </summary>
public sealed class ProfileSimulationService
{
    private readonly MeterRegistry _registry;
    private readonly MeterSessionManager _sessions;
    private readonly PushCoordinator _push;
    private readonly ProfileSimulationOptions _options;
    private readonly TimeZoneInfo _timeZone;
    private readonly ILogger<ProfileSimulationService> _logger;

    // In-memory only, per (batch, profile) — Instantaneous has no buffer/history to anchor on, so
    // "when did we last nudge it" only needs to survive within one process lifetime. A restart
    // simply resumes on the next due boundary, which is harmless for a "current value" profile.
    private readonly ConcurrentDictionary<(int BatchId, string LogicalName), DateTimeOffset> _lastInstantaneousAdvanceUtc = new();

    public ProfileSimulationService(
        MeterRegistry registry,
        MeterSessionManager sessions,
        PushCoordinator push,
        IOptions<ProfileSimulationOptions> options,
        ILogger<ProfileSimulationService> logger)
    {
        _registry = registry;
        _sessions = sessions;
        _push = push;
        _options = options.Value;
        _logger = logger;
        _timeZone = ResolveTimeZone(_options);
        ValidateOptions(_options);
    }

    public bool Enabled => _options.Enabled && _options.Profiles.Count > 0;

    /// <summary>
    /// Advances one batch through every due, configured profile capture. Idempotent for a repeated
    /// clock value because each next boundary is strictly after the latest saved capture.
    /// </summary>
    public async Task<ProfileAdvanceResult> AdvanceBatch(MeterBatch batch, DateTimeOffset nowUtc, CancellationToken cancellationToken = default)
    {
        if (!Enabled)
        {
            return ProfileAdvanceResult.Disabled(batch.Id);
        }

        BatchProfileSimulationState? batchState = _sessions.GetOrCreateBatchProfileState(batch);
        if (batchState is null)
        {
            return ProfileAdvanceResult.NotAdvanced(batch.Id, "Profile simulation working state could not be resolved for this batch.");
        }

        var captured = new List<ProfileCaptureResult>();
        var skipped = new List<string>();
        var autoPushProfiles = new List<string>();

        IReadOnlyDictionary<string, ProfileBufferState> bufferStates = batchState.GetProfileBufferStates()
            .ToDictionary(state => state.LogicalName, StringComparer.Ordinal);
        IReadOnlyCollection<DLMSMeter> metersToSync = _sessions.GetMaterializedMeters(batch);

        foreach (ProfileSimulationProfile configured in _options.Profiles)
        {
            IReadOnlyDictionary<string, decimal> increments = configured.ValueIncrements
                .ToDictionary(value => value.CaptureObjectLogicalName, value => value.IncrementPerCapture, StringComparer.Ordinal);

            if (configured.CaptureRule == ProfileCaptureRule.Instantaneous)
            {
                AdvanceInstantaneous(batch, batchState, configured, increments, metersToSync, nowUtc, captured, skipped);
                continue;
            }

            if (!bufferStates.TryGetValue(configured.LogicalName, out ProfileBufferState state))
            {
                skipped.Add($"{configured.LogicalName}: not present in template");
                continue;
            }

            if (state.LatestCaptureAtUtc is null)
            {
                skipped.Add($"{configured.LogicalName}: no timestamped seed record");
                continue;
            }

            int periodSeconds = configured.CaptureRule == ProfileCaptureRule.FixedPeriod
                ? (configured.CapturePeriodSeconds > 0 ? configured.CapturePeriodSeconds : checked((int)state.CapturePeriodSeconds))
                : 0;
            if (configured.CaptureRule == ProfileCaptureRule.FixedPeriod && periodSeconds <= 0)
            {
                skipped.Add($"{configured.LogicalName}: no configured capture period");
                continue;
            }

            DateTimeOffset lastCompletedBoundary = CompletedBoundary(nowUtc, configured.CaptureRule, periodSeconds);
            DateTimeOffset next = NextBoundaryAfter(state.LatestCaptureAtUtc.Value, configured.CaptureRule, periodSeconds);

            int generatedForProfile = 0;
            bool profileCaptured = false;
            while (next <= lastCompletedBoundary && generatedForProfile < _options.MaxCapturesPerCycle)
            {
                captured.Add(batchState.AppendCapture(configured.LogicalName, next, increments, metersToSync));
                profileCaptured = true;
                generatedForProfile++;
                next = NextBoundaryAfter(next, configured.CaptureRule, periodSeconds);
            }

            if (next <= lastCompletedBoundary)
            {
                skipped.Add($"{configured.LogicalName}: catch-up limit {_options.MaxCapturesPerCycle} reached");
            }

            if (profileCaptured && configured.AutoPush)
            {
                // AutoPushSetupLogicalName, not LogicalName — the PushSetup's own dispatch OBIS is a
                // different value from the profile's own identity (see ProfileSimulationOptions.cs).
                // ValidateOptions already guarantees this is non-empty whenever AutoPush is true.
                autoPushProfiles.Add(configured.AutoPushSetupLogicalName!);
            }
        }

        if (captured.Count > 0)
        {
            // The working XML becomes durable before this method reports new records, so a crash
            // right after can't leave a generated record acknowledged but unrecoverable.
            _sessions.SaveProfileWorkingState(batch, batchState);
            _logger.LogInformation(
                "Generated {Count} profile capture(s) for batch {Batch} through {NowUtc:u}",
                captured.Count, batch.Name, nowUtc);
        }

        foreach (string pushSetupLogicalName in autoPushProfiles)
        {
            try
            {
                PushBatchResult result = await _push.PushBatchAsync(batch.Id, destination: null, cancellationToken, pushSetupLogicalName: pushSetupLogicalName);
                if (!result.Ok)
                {
                    _logger.LogWarning("Auto-push failed for batch {Batch}, PushSetup {PushSetup}: {Error}", batch.Name, pushSetupLogicalName, result.Error);
                    skipped.Add($"{pushSetupLogicalName}: auto-push failed ({result.Error})");
                }
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Auto-push failed for batch {Batch}, PushSetup {PushSetup}", batch.Name, pushSetupLogicalName);
                skipped.Add($"{pushSetupLogicalName}: auto-push failed ({exception.Message})");
            }
        }

        return new ProfileAdvanceResult(batch.Id, captured, skipped, false, null);
    }

    private void AdvanceInstantaneous(
        MeterBatch batch,
        BatchProfileSimulationState batchState,
        ProfileSimulationProfile configured,
        IReadOnlyDictionary<string, decimal> increments,
        IReadOnlyCollection<DLMSMeter> metersToSync,
        DateTimeOffset nowUtc,
        List<ProfileCaptureResult> captured,
        List<string> skipped)
    {
        if (configured.CapturePeriodSeconds <= 0)
        {
            skipped.Add($"{configured.LogicalName}: no configured capture period");
            return;
        }

        DateTimeOffset lastCompletedBoundary = CompletedBoundary(nowUtc, ProfileCaptureRule.FixedPeriod, configured.CapturePeriodSeconds);
        var key = (batch.Id, configured.LogicalName);
        DateTimeOffset lastAdvanced = _lastInstantaneousAdvanceUtc.GetOrAdd(key, DateTimeOffset.MinValue);
        if (lastAdvanced >= lastCompletedBoundary)
        {
            return;
        }

        try
        {
            batchState.AdvanceInstantaneous(configured.LogicalName, increments, metersToSync);
            _lastInstantaneousAdvanceUtc[key] = lastCompletedBoundary;
            captured.Add(new ProfileCaptureResult(configured.LogicalName, lastCompletedBoundary, 0, 0));
        }
        catch (InvalidOperationException exception)
        {
            skipped.Add($"{configured.LogicalName}: {exception.Message}");
        }
    }

    /// <summary>Advances a bounded round-robin slice of every running batch.</summary>
    public async Task<IReadOnlyList<ProfileAdvanceResult>> AdvanceRunningBatches(DateTimeOffset nowUtc, CancellationToken cancellationToken = default)
    {
        if (!Enabled)
        {
            return Array.Empty<ProfileAdvanceResult>();
        }

        var results = new List<ProfileAdvanceResult>();
        foreach (MeterBatch batch in _registry.Batches.Where(batch => batch.Status == BatchStatus.Running))
        {
            results.Add(await AdvanceBatch(batch, nowUtc, cancellationToken));
        }

        return results;
    }

    private DateTimeOffset CompletedBoundary(DateTimeOffset nowUtc, ProfileCaptureRule rule, int periodSeconds)
    {
        DateTimeOffset local = TimeZoneInfo.ConvertTime(nowUtc, _timeZone);
        return rule switch
        {
            ProfileCaptureRule.DailyMidnight => DayStart(local).ToUniversalTime(),
            ProfileCaptureRule.MonthlyFirst => MonthStart(local).ToUniversalTime(),
            _ => FixedPeriodBoundary(local, periodSeconds).ToUniversalTime(),
        };
    }

    private DateTimeOffset NextBoundaryAfter(DateTimeOffset timestampUtc, ProfileCaptureRule rule, int periodSeconds)
    {
        DateTimeOffset local = TimeZoneInfo.ConvertTime(timestampUtc, _timeZone);
        return rule switch
        {
            ProfileCaptureRule.DailyMidnight => DayStart(local).AddDays(1).ToUniversalTime(),
            ProfileCaptureRule.MonthlyFirst => MonthStart(local).AddMonths(1).ToUniversalTime(),
            _ => FixedPeriodNextBoundary(local, periodSeconds).ToUniversalTime(),
        };
    }

    private static DateTimeOffset DayStart(DateTimeOffset local) =>
        new(local.Year, local.Month, local.Day, 0, 0, 0, local.Offset);

    private static DateTimeOffset MonthStart(DateTimeOffset local) =>
        new(local.Year, local.Month, 1, 0, 0, 0, local.Offset);

    private static DateTimeOffset FixedPeriodBoundary(DateTimeOffset local, int periodSeconds)
    {
        DateTimeOffset dayStart = DayStart(local);
        long elapsedSeconds = (long)Math.Floor((local - dayStart).TotalSeconds);
        return dayStart.AddSeconds(elapsedSeconds / periodSeconds * periodSeconds);
    }

    private static DateTimeOffset FixedPeriodNextBoundary(DateTimeOffset local, int periodSeconds)
    {
        DateTimeOffset dayStart = DayStart(local);
        long elapsedSeconds = (long)Math.Floor((local - dayStart).TotalSeconds);
        return dayStart.AddSeconds((elapsedSeconds / periodSeconds + 1) * periodSeconds);
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

        if (options.MaxCapturesPerCycle is < 1 or > 10_000)
        {
            throw new InvalidOperationException("ProfileSimulation:MaxCapturesPerCycle must be between 1 and 10000.");
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

            if (profile.CaptureRule == ProfileCaptureRule.Instantaneous && profile.AutoPush)
            {
                throw new InvalidOperationException(
                    $"ProfileSimulation profile '{profile.LogicalName}' is Instantaneous and cannot use automatic push — " +
                    "IP data can only be sent via the manual Send Push Now action. Set AutoPush to false.");
            }

            if (profile.AutoPush && string.IsNullOrWhiteSpace(profile.AutoPushSetupLogicalName))
            {
                throw new InvalidOperationException(
                    $"ProfileSimulation profile '{profile.LogicalName}' has AutoPush enabled but no AutoPushSetupLogicalName. " +
                    "This must be the PushSetup's own OBIS (e.g. Daily's push dispatch code), not the profile's own LogicalName — " +
                    "they are different values for every profile type.");
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

/// <summary>One read-only result from advancing a batch.</summary>
public sealed record ProfileAdvanceResult(
    int BatchId,
    IReadOnlyList<ProfileCaptureResult> Captures,
    IReadOnlyList<string> Skipped,
    bool IsDisabled,
    string? Error)
{
    public static ProfileAdvanceResult Disabled(int batchId) =>
        new(batchId, Array.Empty<ProfileCaptureResult>(), Array.Empty<string>(), true, null);

    public static ProfileAdvanceResult NotAdvanced(int batchId, string reason) =>
        new(batchId, Array.Empty<ProfileCaptureResult>(), [reason], false, null);
}
