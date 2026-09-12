using Gurux.DLMS.Objects;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.ProfileSimulation;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace ManyMeterSimulator.Tests;

public sealed class ProfileSimulationServiceTests : IDisposable
{
    private const string ProfileLogicalName = "1.0.94.91.0.255";
    private readonly string _root = Path.Combine(Path.GetTempPath(), "MeterSimulator-profile-simulation-service-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public void AdvanceMeter_GeneratesAndReloadsOneCompletedCapture_WithoutRepeatingIt()
    {
        Directory.CreateDirectory(_root);
        var options = new ProfileSimulationOptions
        {
            Enabled = true,
            TimeZoneId = "UTC",
            MaxMetersPerBatchPerCycle = 1,
            MaxCapturesPerMeterPerCycle = 1,
            Profiles =
            [
                new ProfileSimulationProfile
                {
                    LogicalName = ProfileLogicalName,
                    CapturePeriodSeconds = 15 * 60,
                },
            ],
        };

        var registry = new MeterRegistry();
        MeterBatch batch = registry.AddBatch("profile-service", "HP_Template_111.xml", 1, NicType.Tcp4G);
        Assert.True(registry.TryStart(batch.Id));

        var templates = new TemplateRegistry(
            Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
            new TestEnvironment(),
            NullLogger<TemplateRegistry>.Instance);
        var stateStore = new ProfileSimulationStateStore(options, _root);
        var sessions = new MeterSessionManager(
            registry,
            templates,
            Options.Create(new BrainOptions()),
            Options.Create(new TcpOptions()),
            NullLogger<MeterSessionManager>.Instance,
            stateStore);
        var service = new ProfileSimulationService(
            registry,
            sessions,
            Options.Create(options),
            NullLogger<ProfileSimulationService>.Instance);
        var meter = new MeterRef(batch.StartIndex, NicType.Tcp4G);

        DLMSServerSession initialSession = sessions.GetOrCreate(meter);
        ProfileBufferState before = Assert.Single(initialSession.GetProfileBufferStates(), state => state.LogicalName == ProfileLogicalName);
        DateTimeOffset expectedCapture = NextUtcBoundary(before.LatestCaptureAtUtc!.Value, 15 * 60);

        ProfileAdvanceResult first = service.AdvanceMeter(meter, expectedCapture.AddSeconds(1));

        ProfileCaptureResult capture = Assert.Single(first.Captures);
        Assert.Equal(ProfileLogicalName, capture.LogicalName);
        Assert.Equal(expectedCapture, capture.CapturedAtUtc);
        Assert.Empty(first.Skipped);

        // Force a load from the XML state instead of reusing the in-memory object graph.
        sessions.ClearBatch(batch.Id);
        DLMSServerSession reloadedSession = sessions.GetOrCreate(meter);
        ProfileBufferState after = Assert.Single(reloadedSession.GetProfileBufferStates(), state => state.LogicalName == ProfileLogicalName);
        Assert.Equal(expectedCapture, after.LatestCaptureAtUtc);
        Assert.Equal(before.Capacity, after.EntriesInUse);

        ProfileAdvanceResult repeated = service.AdvanceMeter(meter, expectedCapture.AddSeconds(1));
        Assert.Empty(repeated.Captures);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static DateTimeOffset NextUtcBoundary(DateTimeOffset timestampUtc, int periodSeconds)
    {
        DateTimeOffset timestamp = timestampUtc.ToUniversalTime();
        var dayStart = new DateTimeOffset(timestamp.Year, timestamp.Month, timestamp.Day, 0, 0, 0, TimeSpan.Zero);
        long elapsedSeconds = (long)Math.Floor((timestamp - dayStart).TotalSeconds);
        return dayStart.AddSeconds((elapsedSeconds / periodSeconds + 1) * periodSeconds);
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
