namespace ManyMeterSimulator.ProfileSimulation;

/// <summary>
/// Reclaims stale per-meter profile-simulation state folders on a daily cadence. This runs
/// unconditionally — including while <see cref="ProfileSimulationOptions.Enabled"/> is false —
/// because a folder left over from when the feature was on, or from a build that no longer
/// references it, still needs to be reclaimed. Tying cleanup to the "is capture generation
/// currently on" flag is exactly what let one build's state folder accumulate ~20,000 orphaned
/// files with nothing ever removing them.
/// </summary>
public sealed class ProfileStateRetentionService : BackgroundService
{
    private static readonly TimeSpan SweepInterval = TimeSpan.FromHours(24);

    private readonly ProfileSimulationStateStore _store;
    private readonly ILogger<ProfileStateRetentionService> _logger;

    public ProfileStateRetentionService(ProfileSimulationStateStore store, ILogger<ProfileStateRetentionService> logger)
    {
        _store = store;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(SweepInterval);
        do
        {
            Sweep();
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    // A sweep at startup — rather than waiting for the first 24h tick — is what would have caught
    // the production incident this guards against on the very next deploy instead of up to a day
    // later.
    private void Sweep()
    {
        try
        {
            int removed = _store.PruneStale(DateTimeOffset.UtcNow);
            if (removed > 0)
            {
                _logger.LogInformation("Profile simulation state sweep removed {Count} stale meter folder(s).", removed);
            }
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Profile simulation state retention sweep failed.");
        }
    }
}
