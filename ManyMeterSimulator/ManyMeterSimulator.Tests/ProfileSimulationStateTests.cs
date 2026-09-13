using Gurux.DLMS;
using Gurux.DLMS.Objects;
using ManyMeterSimulator.ProfileSimulation;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Xunit;

namespace ManyMeterSimulator.Tests;

public sealed class ProfileSimulationStateTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "MeterSimulator-profile-simulation-tests", Guid.NewGuid().ToString("N"));

    private static string TemplatePath() => Path.Combine(AppContext.BaseDirectory, "Templates", "HP_Template_111.xml");

    [Fact]
    public void WorkingState_CreatesOneSharedModelForTheBatch_AndRejectsSourceTemplateReplacement()
    {
        Directory.CreateDirectory(_root);
        string source = TemplatePath();
        string alternate = Path.Combine(_root, "alternate.xml");
        File.Copy(source, alternate);
        File.AppendAllText(alternate, Environment.NewLine);

        var store = new ProfileSimulationStateStore(new ProfileSimulationOptions { Enabled = true }, _root);
        MeterBatch batch = Batch();

        Assert.True(store.TryGetOrCreate(batch, source, out ProfileWorkingModel model));
        Assert.False(string.Equals(Path.GetFullPath(source), model.ModelPath, StringComparison.OrdinalIgnoreCase));
        Assert.True(File.Exists(model.ModelPath));
        Assert.True(File.Exists(model.MetadataPath));
        Assert.NotEmpty(GXDLMSObjectCollection.Load(model.ModelPath));

        // A second meter in the SAME batch resolves to the exact same file — there is one working
        // model per batch, not one per meter.
        Assert.True(store.TryGetOrCreate(batch, source, out ProfileWorkingModel again));
        Assert.Equal(model.ModelPath, again.ModelPath);

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            store.TryGetOrCreate(batch, alternate, out _));
        Assert.Contains("different batch definition or source template", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SavedWorkingModel_PreservesGeneratedTimestamp_AndRetainsPreviousSnapshot()
    {
        Directory.CreateDirectory(_root);
        var store = new ProfileSimulationStateStore(new ProfileSimulationOptions { Enabled = true }, _root);
        MeterBatch batch = Batch();
        Assert.True(store.TryGetOrCreate(batch, TemplatePath(), out ProfileWorkingModel model));

        var batchState = new BatchProfileSimulationState(model.ModelPath);
        ProfileBufferState before = Assert.Single(batchState.GetProfileBufferStates(), state => state.LogicalName == "1.0.94.91.0.255");
        DateTimeOffset capturedAt = before.LatestCaptureAtUtc!.Value.AddMinutes(15);

        ProfileCaptureResult result = batchState.AppendCapture("1.0.94.91.0.255", capturedAt, null, Array.Empty<DLMSMeter>());
        Assert.Equal((int)before.Capacity, result.RetainedCount);
        Assert.Equal(1, result.EvictedCount);
        store.Save(model, batchState.Save);

        Assert.True(File.Exists(model.PreviousModelPath));
        var loaded = new GXDLMSObjectCollection();
        new MeterObjectLoader(model.ModelPath).Load(loaded, shiftProfileTimestamps: false);
        var profile = Assert.IsType<GXDLMSProfileGeneric>(loaded.FindByLN(Gurux.DLMS.Enums.ObjectType.ProfileGeneric, "1.0.94.91.0.255"));
        DateTimeOffset latest = profile.Buffer.Max(row => Assert.IsType<GXDateTime>(row[0]).Value);
        Assert.Equal(capturedAt, latest);
        Assert.Equal(before.Capacity, profile.EntriesInUse);
    }

    [Fact]
    public void TwoMetersInTheSameBatch_ShareTheExactSameSimulationObjectGraph()
    {
        Directory.CreateDirectory(_root);
        var store = new ProfileSimulationStateStore(new ProfileSimulationOptions { Enabled = true }, _root);
        MeterBatch batch = Batch();
        Assert.True(store.TryGetOrCreate(batch, TemplatePath(), out ProfileWorkingModel model));

        var meterA = new DLMSMeter(1, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        var sessionA = new DLMSServerSession(meterA, model.ModelPath, shiftProfileTimestamps: false);
        sessionA.Initialize(true);

        var meterB = new DLMSMeter(2, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 2);
        var sessionB = new DLMSServerSession(meterB, model.ModelPath, shiftProfileTimestamps: false);
        sessionB.Initialize(true);

        var profileA = Assert.IsType<GXDLMSProfileGeneric>(
            sessionA.Items.FindByLN(Gurux.DLMS.Enums.ObjectType.ProfileGeneric, "1.0.94.91.0.255"));
        var profileB = Assert.IsType<GXDLMSProfileGeneric>(
            sessionB.Items.FindByLN(Gurux.DLMS.Enums.ObjectType.ProfileGeneric, "1.0.94.91.0.255"));

        // Same working-XML path -> TemplateModelCache hands back the identical GXDLMSObjectCollection
        // to both sessions, so their profile OBJECTS (not just equal values) are the same instance.
        Assert.Same(profileA, profileB);

        var batchState = new BatchProfileSimulationState(model.ModelPath);
        DateTimeOffset seedLatest = Assert.Single(
            batchState.GetProfileBufferStates(), state => state.LogicalName == "1.0.94.91.0.255").LatestCaptureAtUtc!.Value;
        DateTimeOffset capturedAt = seedLatest.AddMinutes(15);

        batchState.AppendCapture("1.0.94.91.0.255", capturedAt, null, [meterA, meterB]);

        // A single generation call, never told about either session individually, is visible from
        // BOTH sessions' own object references — proving the batch produced one shared timeline.
        Assert.Contains(profileA.Buffer, row => row[0] is GXDateTime timestamp && timestamp.Value == capturedAt);
        Assert.Contains(profileB.Buffer, row => row[0] is GXDateTime timestamp && timestamp.Value == capturedAt);
    }

    [Fact]
    public void PruneStale_RemovesOnlyBatchesUntouchedPastRetention()
    {
        Directory.CreateDirectory(_root);
        var options = new ProfileSimulationOptions { Enabled = true, StateRetentionDays = 45 };
        var store = new ProfileSimulationStateStore(options, _root);

        Assert.True(store.TryGetOrCreate(Batch(id: 101), TemplatePath(), out ProfileWorkingModel stale));
        Assert.True(store.TryGetOrCreate(Batch(id: 102), TemplatePath(), out ProfileWorkingModel fresh));

        DateTime old = DateTime.UtcNow.AddDays(-46);
        foreach (string file in Directory.EnumerateFiles(Path.GetDirectoryName(stale.ModelPath)!))
        {
            File.SetLastWriteTimeUtc(file, old);
        }

        int removed = store.PruneStale(DateTimeOffset.UtcNow);

        Assert.Equal(1, removed);
        Assert.False(Directory.Exists(Path.GetDirectoryName(stale.ModelPath)));
        Assert.True(File.Exists(fresh.ModelPath));
    }

    [Fact]
    public void WorkingState_RestoresPreviousXml_WhenCurrentXmlIsCorrupt()
    {
        Directory.CreateDirectory(_root);
        var store = new ProfileSimulationStateStore(new ProfileSimulationOptions { Enabled = true }, _root);
        MeterBatch batch = Batch();
        Assert.True(store.TryGetOrCreate(batch, TemplatePath(), out ProfileWorkingModel model));

        store.Save(model, path => File.Copy(model.ModelPath, path));
        File.WriteAllText(model.ModelPath, "<not-valid-xml");

        Assert.True(store.TryGetOrCreate(batch, TemplatePath(), out ProfileWorkingModel restored));
        Assert.Equal(model.ModelPath, restored.ModelPath);
        Assert.NotEmpty(GXDLMSObjectCollection.Load(restored.ModelPath));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static MeterBatch Batch(int id = 101) => new()
    {
        Id = id,
        Name = $"profile-simulation-test-{id}",
        TemplateName = "HP_Template_111.xml",
        StartIndex = 1,
        Count = 2,
        CreatedAtUtc = new DateTimeOffset(2026, 9, 12, 0, 0, 0, TimeSpan.Zero),
    };
}
