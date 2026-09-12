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
    public void WorkingState_CreatesSeparateModel_AndRejectsSourceTemplateReplacement()
    {
        Directory.CreateDirectory(_root);
        string source = TemplatePath();
        string alternate = Path.Combine(_root, "alternate.xml");
        File.Copy(source, alternate);
        File.AppendAllText(alternate, Environment.NewLine);

        var store = new ProfileSimulationStateStore(new ProfileSimulationOptions { Enabled = true }, _root);
        MeterBatch batch = Batch();

        Assert.True(store.TryGetOrCreate(batch, meterIndex: 1, source, out ProfileWorkingModel model));
        Assert.False(string.Equals(Path.GetFullPath(source), model.ModelPath, StringComparison.OrdinalIgnoreCase));
        Assert.True(File.Exists(model.ModelPath));
        Assert.True(File.Exists(model.MetadataPath));
        Assert.NotEmpty(GXDLMSObjectCollection.Load(model.ModelPath));

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() =>
            store.TryGetOrCreate(batch, meterIndex: 1, alternate, out _));
        Assert.Contains("different batch or source template", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SavedWorkingModel_PreservesGeneratedTimestamp_AndRetainsPreviousSnapshot()
    {
        Directory.CreateDirectory(_root);
        var store = new ProfileSimulationStateStore(new ProfileSimulationOptions { Enabled = true }, _root);
        MeterBatch batch = Batch();
        Assert.True(store.TryGetOrCreate(batch, meterIndex: 1, TemplatePath(), out ProfileWorkingModel model));

        var meter = new DLMSMeter(1, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        var session = new DLMSServerSession(
            meter,
            model.ModelPath,
            shiftProfileTimestamps: false);
        session.Initialize(true);

        ProfileBufferState before = Assert.Single(session.GetProfileBufferStates(), state => state.LogicalName == "1.0.94.91.0.255");
        DateTimeOffset capturedAt = before.LatestCaptureAtUtc!.Value.AddMinutes(15);

        ProfileCaptureResult result = session.AppendProfileCapture("1.0.94.91.0.255", capturedAt);
        Assert.Equal((int)before.Capacity, result.RetainedCount);
        Assert.Equal(1, result.EvictedCount);
        store.Save(model, session.SaveWorkingModel);

        Assert.True(File.Exists(model.PreviousModelPath));
        var loaded = new GXDLMSObjectCollection();
        new MeterObjectLoader(model.ModelPath).Load(loaded, shiftProfileTimestamps: false);
        var profile = Assert.IsType<GXDLMSProfileGeneric>(loaded.FindByLN(Gurux.DLMS.Enums.ObjectType.ProfileGeneric, "1.0.94.91.0.255"));
        DateTimeOffset latest = profile.Buffer.Max(row => Assert.IsType<GXDateTime>(row[0]).Value);
        Assert.Equal(capturedAt, latest);
        Assert.Equal(before.Capacity, profile.EntriesInUse);
        var serial = Assert.IsType<GXDLMSData>(loaded.FindByLN(Gurux.DLMS.Enums.ObjectType.Data, "0.0.96.1.0.255"));
        Assert.Equal(meter.MeterNo, serial.Value);
    }

    [Fact]
    public void WorkingState_RestoresPreviousXml_WhenCurrentXmlIsCorrupt()
    {
        Directory.CreateDirectory(_root);
        var store = new ProfileSimulationStateStore(new ProfileSimulationOptions { Enabled = true }, _root);
        MeterBatch batch = Batch();
        Assert.True(store.TryGetOrCreate(batch, meterIndex: 1, TemplatePath(), out ProfileWorkingModel model));

        store.Save(model, path => File.Copy(model.ModelPath, path));
        File.WriteAllText(model.ModelPath, "<not-valid-xml");

        Assert.True(store.TryGetOrCreate(batch, meterIndex: 1, TemplatePath(), out ProfileWorkingModel restored));
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

    private static MeterBatch Batch() => new()
    {
        Id = 101,
        Name = "profile-simulation-test",
        TemplateName = "HP_Template_111.xml",
        StartIndex = 1,
        Count = 1,
        CreatedAtUtc = new DateTimeOffset(2026, 9, 12, 0, 0, 0, TimeSpan.Zero),
    };
}
