using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Fota;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.Fota;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Gurux.DLMS.Enums;

namespace ManyMeterSimulator.Tests;

public sealed class FotaServiceTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "maya-fota-service-" + Guid.NewGuid().ToString("N"));
    private readonly TemplateRegistry _templates = new(
        Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
        new TestEnvironment(), NullLogger<TemplateRegistry>.Instance);

    private FotaService Service() => new(_templates, _root, new FotaLimits());

    [Fact]
    public void SettingsOverridesAndProgressSurviveRestart_AndBindToRealSessions()
    {
        var registry = new MeterRegistry();
        var batch = registry.AddBatch("FOTA", "SA1231166HP_values.xml", 60);
        var service = Service();
        Assert.False(service.Settings(batch).Enabled);
        service.SaveSettings(batch, null, new FotaSettings { Enabled = true, TargetVersion = "BATCH", BlockSize = 32 });
        service.SaveSettings(batch, 1, new FotaSettings { Enabled = true, TargetVersion = "METER", BlockSize = 64 });

        service = Service();
        Assert.Equal("METER", service.Settings(batch, 1).TargetVersion);
        Assert.Equal("BATCH", service.Settings(batch, 2).TargetVersion);
        var sessions = new MeterSessionManager(registry, _templates, Options.Create(new BrainOptions()),
            Options.Create(new TcpOptions { AddressPrefix = "fd00:6d65:7472::/64" }),
            NullLogger<MeterSessionManager>.Instance, fota: service);
        var first = sessions.GetOrCreate(new MeterRef(1, NicType.Tcp4G));
        Assert.NotNull(first.Fota);
        Assert.Equal(ErrorCode.Ok, first.Fota.Invoke(1, new object[] { new byte[] { 1 }, 64U }));
        service.RemoveOverride(batch, 1);
        Assert.Equal(64U, first.Fota.Read(2));
        Assert.Equal(ErrorCode.Ok, first.Fota.Invoke(2, new object[] { 0U, new byte[64] }));
        Assert.Equal(ErrorCode.Ok, first.Fota.Invoke(3, 0));
        Assert.Equal(ErrorCode.Ok, first.Fota.Invoke(4, 0));

        service = Service();
        var rows = service.Progress(batch, 1);
        Assert.Equal(50, rows.Count);
        Assert.Equal("METER", rows[0].CurrentVersion);
        Assert.Equal("ActivationSuccessful", rows[0].Status);
        Assert.Equal(10, service.Progress(batch, 51).Count);
        service.Reset(batch, 1);
        Assert.Equal("METER", Service().Progress(batch, 1)[0].CurrentVersion);
        Assert.Equal(0, Service().Progress(batch, 1)[0].Total);
        Assert.Equal("BATCH", service.Settings(batch, 1).TargetVersion);
    }

    [Fact]
    public void UnsupportedTemplatesAndOutOfBatchOverridesAreRejected()
    {
        var registry = new MeterRegistry();
        var batch = registry.AddBatch("No FOTA", "SZ0000014HP_Only_Push.xml", 2);
        var service = Service();
        Assert.False(service.Supported(batch));
        Assert.Null(service.Bind(batch, 1));
        Assert.Throws<ArgumentException>(() => service.SaveSettings(batch, null, new() { Enabled = true, TargetVersion = "BAD" }));
        Assert.Throws<ArgumentException>(() => service.SaveSettings(batch, 3, new()));
        Assert.Throws<ArgumentException>(() => service.Reset(batch, 3));
    }

    [Fact]
    public void ReusedMeterAddressesDoNotInheritOldBatchState()
    {
        var first = new MeterBatch { Id = 1, Name = "first", TemplateName = "SA1231166HP_values.xml", StartIndex = 1, Count = 1 };
        var second = new MeterBatch
        {
            Id = 1, Name = "second", TemplateName = first.TemplateName, StartIndex = 1, Count = 1,
            CreatedAtUtc = first.CreatedAtUtc.AddSeconds(1)
        };
        var service = Service();
        service.SaveSettings(first, null, new() { Enabled = true, TargetVersion = "FIRST" });
        Assert.Equal(ErrorCode.Ok, service.Bind(first, 1)!.Invoke(1, new object[] { new byte[] { 1 }, 20U }));
        Assert.False(service.Settings(second).Enabled);
        Assert.Equal(0, service.Progress(second, 1)[0].Total);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, true);
        }
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Testing";
        public string ApplicationName { get; set; } = "FotaTests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
