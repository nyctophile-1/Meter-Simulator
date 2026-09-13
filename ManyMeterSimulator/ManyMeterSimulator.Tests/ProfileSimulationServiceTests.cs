using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Push;
using ManyMeterSimulator.Networking.Registry;
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
    public async Task AdvanceBatch_GeneratesAndReloadsOneCompletedCapture_WithoutRepeatingIt()
    {
        var options = new ProfileSimulationOptions
        {
            Enabled = true,
            TimeZoneId = "UTC",
            MaxCapturesPerCycle = 1,
            Profiles =
            [
                new ProfileSimulationProfile
                {
                    LogicalName = ProfileLogicalName,
                    CapturePeriodSeconds = 15 * 60,
                    AutoPush = false,
                },
            ],
        };

        (ProfileSimulationService service, MeterSessionManager sessions, MeterBatch batch) = NewHarness(options);

        BatchProfileSimulationState? initialState = sessions.GetOrCreateBatchProfileState(batch);
        ProfileBufferState before = Assert.Single(initialState!.GetProfileBufferStates(), state => state.LogicalName == ProfileLogicalName);
        DateTimeOffset expectedCapture = NextUtcBoundary(before.LatestCaptureAtUtc!.Value, 15 * 60);

        ProfileAdvanceResult first = await service.AdvanceBatch(batch, expectedCapture.AddSeconds(1));

        ProfileCaptureResult capture = Assert.Single(first.Captures);
        Assert.Equal(ProfileLogicalName, capture.LogicalName);
        Assert.Equal(expectedCapture, capture.CapturedAtUtc);
        Assert.Empty(first.Skipped);

        // Load the working XML independently of TemplateModelCache (which caches forever by path,
        // same as the shared static-template cache) to prove the capture actually reached disk, not
        // just the in-memory object graph.
        var loaded = new Gurux.DLMS.Objects.GXDLMSObjectCollection();
        new MeterObjectLoader(WorkingModelPath(batch)).Load(loaded, shiftProfileTimestamps: false);
        var savedProfile = Assert.IsType<Gurux.DLMS.Objects.GXDLMSProfileGeneric>(
            loaded.FindByLN(Gurux.DLMS.Enums.ObjectType.ProfileGeneric, ProfileLogicalName));
        Assert.Equal(before.Capacity, savedProfile.EntriesInUse);
        Assert.Contains(savedProfile.Buffer, row => row[0] is Gurux.DLMS.GXDateTime ts && ts.Value == expectedCapture);

        ProfileAdvanceResult repeated = await service.AdvanceBatch(batch, expectedCapture.AddSeconds(1));
        Assert.Empty(repeated.Captures);
    }

    private string WorkingModelPath(MeterBatch batch) => Path.Combine(_root, $"batch-{batch.Id:D6}", "model.xml");

    [Fact]
    public async Task AdvanceBatch_DailyMidnight_GeneratesExactlyOneRecordAtLocalMidnight()
    {
        var options = new ProfileSimulationOptions
        {
            Enabled = true,
            TimeZoneId = "UTC",
            MaxCapturesPerCycle = 10,
            Profiles =
            [
                new ProfileSimulationProfile
                {
                    LogicalName = ProfileLogicalName,
                    CaptureRule = ProfileCaptureRule.DailyMidnight,
                    AutoPush = false,
                },
            ],
        };

        (ProfileSimulationService service, MeterSessionManager sessions, MeterBatch batch) = NewHarness(options);
        BatchProfileSimulationState state = sessions.GetOrCreateBatchProfileState(batch)!;
        DateTimeOffset seedLatest = Assert.Single(state.GetProfileBufferStates(), s => s.LogicalName == ProfileLogicalName).LatestCaptureAtUtc!.Value;
        DateTimeOffset nextMidnight = new DateTimeOffset(seedLatest.Date, TimeSpan.Zero).AddDays(1);

        ProfileAdvanceResult result = await service.AdvanceBatch(batch, nextMidnight.AddMinutes(5));

        ProfileCaptureResult capture = Assert.Single(result.Captures);
        Assert.Equal(nextMidnight, capture.CapturedAtUtc);
    }

    [Fact]
    public async Task AdvanceBatch_MonthlyFirst_ClosesThePriorCalendarMonth()
    {
        var options = new ProfileSimulationOptions
        {
            Enabled = true,
            TimeZoneId = "UTC",
            MaxCapturesPerCycle = 10,
            Profiles =
            [
                new ProfileSimulationProfile
                {
                    LogicalName = ProfileLogicalName,
                    CaptureRule = ProfileCaptureRule.MonthlyFirst,
                    AutoPush = false,
                },
            ],
        };

        (ProfileSimulationService service, MeterSessionManager sessions, MeterBatch batch) = NewHarness(options);
        BatchProfileSimulationState state = sessions.GetOrCreateBatchProfileState(batch)!;
        DateTimeOffset seedLatest = Assert.Single(state.GetProfileBufferStates(), s => s.LogicalName == ProfileLogicalName).LatestCaptureAtUtc!.Value;
        var firstOfNextMonth = new DateTimeOffset(seedLatest.Year, seedLatest.Month, 1, 0, 0, 0, TimeSpan.Zero).AddMonths(1);

        // Advance "now" to well into the month AFTER the one that should close, so exactly one
        // monthly boundary (firstOfNextMonth) is due — never two, regardless of seed month.
        ProfileAdvanceResult result = await service.AdvanceBatch(batch, firstOfNextMonth.AddDays(3));

        ProfileCaptureResult capture = Assert.Single(result.Captures);
        Assert.Equal(firstOfNextMonth, capture.CapturedAtUtc);
    }

    [Fact]
    public void Constructor_Throws_WhenAnInstantaneousProfileHasAutoPushEnabled()
    {
        var options = new ProfileSimulationOptions
        {
            Enabled = true,
            TimeZoneId = "UTC",
            Profiles =
            [
                new ProfileSimulationProfile
                {
                    LogicalName = "0.0.25.9.0.255",
                    CaptureRule = ProfileCaptureRule.Instantaneous,
                    CapturePeriodSeconds = 60,
                    AutoPush = true,
                },
            ],
        };

        (MeterRegistry registry, MeterSessionManager sessions, PushCoordinator push, _) = NewInfrastructure(options);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            new ProfileSimulationService(registry, sessions, push, Options.Create(options), NullLogger<ProfileSimulationService>.Instance));
        Assert.Contains("cannot use automatic push", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Regression guard for a real latent bug: AutoPush previously passed the profile's own
    /// LogicalName as the PushSetup filter, which is a different OBIS from the actual push dispatch
    /// channel for every profile type (Block Load's own LN "1.0.99.1.0.255" vs. its push OBIS
    /// "0.5.25.9.0.255", Daily's "1.0.99.2.0.255" vs. "0.6.25.9.0.255", etc.) — silently pushing
    /// nothing. AutoPushSetupLogicalName is now a distinct, required field precisely so this can't
    /// be forgotten.
    /// </summary>
    [Fact]
    public void Constructor_Throws_WhenAutoPushEnabled_WithoutAutoPushSetupLogicalName()
    {
        var options = new ProfileSimulationOptions
        {
            Enabled = true,
            TimeZoneId = "UTC",
            Profiles =
            [
                new ProfileSimulationProfile
                {
                    LogicalName = ProfileLogicalName,
                    CapturePeriodSeconds = 15 * 60,
                    AutoPush = true,
                    // AutoPushSetupLogicalName deliberately left unset.
                },
            ],
        };

        (MeterRegistry registry, MeterSessionManager sessions, PushCoordinator push, _) = NewInfrastructure(options);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            new ProfileSimulationService(registry, sessions, push, Options.Create(options), NullLogger<ProfileSimulationService>.Instance));
        Assert.Contains("AutoPushSetupLogicalName", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void BatchProfileSimulationState_AdvanceInstantaneous_Throws_WhenPushSetupIsAbsent()
    {
        Directory.CreateDirectory(_root);
        var stateStore = new ProfileSimulationStateStore(new ProfileSimulationOptions { Enabled = true }, _root);
        MeterBatch batch = MakeBatch();
        Assert.True(stateStore.TryGetOrCreate(batch, TemplatePath(), out ProfileWorkingModel model));
        var state = new BatchProfileSimulationState(model.ModelPath);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            state.AdvanceInstantaneous("9.9.9.9.9.255", new Dictionary<string, decimal>(), Array.Empty<MeterSimulator.Models.DLMSMeter>()));
        Assert.Contains("is not present", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static string TemplatePath() => Path.Combine(AppContext.BaseDirectory, "Templates", "HP_Template_111.xml");

    private static DateTimeOffset NextUtcBoundary(DateTimeOffset timestampUtc, int periodSeconds)
    {
        DateTimeOffset timestamp = timestampUtc.ToUniversalTime();
        var dayStart = new DateTimeOffset(timestamp.Year, timestamp.Month, timestamp.Day, 0, 0, 0, TimeSpan.Zero);
        long elapsedSeconds = (long)Math.Floor((timestamp - dayStart).TotalSeconds);
        return dayStart.AddSeconds((elapsedSeconds / periodSeconds + 1) * periodSeconds);
    }

    private MeterBatch MakeBatch() => new()
    {
        Id = 201,
        Name = "profile-service",
        TemplateName = "HP_Template_111.xml",
        StartIndex = 1,
        Count = 1,
        CreatedAtUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
    };

    private (ProfileSimulationService Service, MeterSessionManager Sessions, MeterBatch Batch) NewHarness(ProfileSimulationOptions options)
    {
        (MeterRegistry registry, MeterSessionManager sessions, PushCoordinator push, MeterBatch batch) = NewInfrastructure(options);
        var service = new ProfileSimulationService(registry, sessions, push, Options.Create(options), NullLogger<ProfileSimulationService>.Instance);
        return (service, sessions, batch);
    }

    private (MeterRegistry Registry, MeterSessionManager Sessions, PushCoordinator Push, MeterBatch Batch) NewInfrastructure(ProfileSimulationOptions options)
    {
        Directory.CreateDirectory(_root);
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

        var network = new NetworkRegistry();
        var tcpPush = new TcpPushSender(NullLogger<TcpPushSender>.Instance, Options.Create(new PushOptions()));
        var push = new PushCoordinator(
            registry, sessions, network, tcpPush, new StubPushPublisher(), new NicCodecFactory(),
            Options.Create(new PushOptions()),
            Options.Create(new CustomPushOptions()),
            new SimulatorMetrics(),
            NullLogger<PushCoordinator>.Instance);

        return (registry, sessions, push, batch);
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    /// <summary>A push publisher with no live clients — mirrors PushDestinationTests' stub.</summary>
    private sealed class StubPushPublisher : IMqttPushPublisher
    {
        public bool HasClient(BrokerBinding binding) => false;

        public Task<bool> TryPublishPushAsync(BrokerBinding binding, NicPublish publish, int qos, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<IMqttPushPool> OpenPoolAsync(BrokerBinding binding, int publisherCount, int qos, int publishTimeoutSeconds, CancellationToken cancellationToken) =>
            throw new NotSupportedException("Not exercised by TCP-batch tests.");
    }
}
