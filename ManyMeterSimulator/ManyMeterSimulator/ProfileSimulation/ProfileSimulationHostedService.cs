using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.ProfileSimulation;

/// <summary>Configuration-gated scheduler for bounded profile simulation work.</summary>
public sealed class ProfileSimulationHostedService : BackgroundService
{
    private readonly ProfileSimulationService _simulation;
    private readonly ProfileSimulationOptions _options;
    private readonly ILogger<ProfileSimulationHostedService> _logger;

    public ProfileSimulationHostedService(
        ProfileSimulationService simulation,
        IOptions<ProfileSimulationOptions> options,
        ILogger<ProfileSimulationHostedService> logger)
    {
        _simulation = simulation;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_simulation.Enabled)
        {
            _logger.LogInformation("Profile simulation is disabled or has no configured profiles.");
            return;
        }

        _logger.LogInformation(
            "Profile simulation started: timezone {TimeZone}, every {IntervalSeconds}s, at most {MetersPerBatch} meter(s) per batch/cycle.",
            _options.TimeZoneId, _options.SchedulerIntervalSeconds, _options.MaxMetersPerBatchPerCycle);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(_options.SchedulerIntervalSeconds));
        do
        {
            try
            {
                await Task.Run(() => _simulation.AdvanceRunningBatches(DateTimeOffset.UtcNow), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Profile simulation scheduler pass failed.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
