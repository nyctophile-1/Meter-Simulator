using System.Buffers.Binary;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.SmartNic;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public class GapBlockCommandTests
{
    private static readonly DateTimeOffset From = new(2026, 9, 10, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(15, 83)]
    [InlineData(30, 167)]
    public void Template93_TwoSelectedRowsDecodeInHesOrder(int period, int energy)
    {
        var (command, inbound, sessions, _) = Setup(3, period);
        var packet = Assert.Single(command.Execute(inbound, CancellationToken.None));
        Assert.Equal(59, packet.Length); // 12 transport + 11 profile + 2 * 18 metadata bytes
        Assert.Equal(1050946u, BinaryPrimitives.ReadUInt32LittleEndian(packet));
        Assert.Equal(0x12345678u, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(8)));
        Assert.Equal(19, packet[12]);
        Assert.Equal(2, packet[13]);
        // Independent reproduction of HES ParseBlock: it visits the last wire row first.
        for (int i = 0; i < 2; i++)
        {
            int offset = 23 + (1 - i) * 18;
            uint timestamp = BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(offset));
            Assert.Equal(From.AddMinutes(i * period), DateTimeOffset.FromUnixTimeSeconds(timestamp).AddMinutes(-330));
            Assert.Equal(23200, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(offset + 4)));
            Assert.Equal(energy, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(offset + 6)));
            Assert.Equal(220, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(offset + 14)));
        }
        Assert.Equal(0, sessions.LiveMeterCount); // GR is synthetic even when other profiles use Meter mode.
    }

    [Fact]
    public void SparseBitmapIncludesBit31WithoutFillingGaps()
    {
        var (command, inbound, _, _) = Setup(0x80000001, 30);
        var packet = Assert.Single(command.Execute(inbound, CancellationToken.None));
        Assert.Equal(59, packet.Length);
        Assert.Equal(From.AddMinutes(31 * 30), DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(23))).AddMinutes(-330));
        Assert.Equal(From, DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(41))).AddMinutes(-330));
    }

    [Fact]
    public void EmptyMaskReturnsNoDataAndOversizedMaskFailsBeforePublishing()
    {
        var (command, inbound, _, _) = Setup(0);
        var packet = Assert.Single(command.Execute(inbound, CancellationToken.None));
        Assert.Equal(23, packet.Length);
        Assert.Equal(100, packet[12]);
        Assert.Equal(0, packet[13]);
        Assert.Throws<NotSupportedException>(() => command.Execute(inbound with { Intent = inbound.Intent with { ValueTo = 0xffff } }, CancellationToken.None));
        Assert.Equal(23 + 15 * 18, Assert.Single(command.Execute(inbound with { Intent = inbound.Intent with { ValueTo = 0x7fff } }, CancellationToken.None)).Length);
    }

    [Fact]
    public void InvalidIntervalBoundaryLimitsAndCancellationFail()
    {
        var (command, inbound, _, options) = Setup(3);
        options.BlockPeriodMinutesByTemplate[93] = 20;
        Assert.Throws<InvalidOperationException>(() => command.Execute(inbound, CancellationToken.None));
        options.BlockPeriodMinutesByTemplate[93] = 15;
        Assert.Throws<ArgumentException>(() => command.Execute(inbound with { Intent = inbound.Intent with { ValueFrom = inbound.Intent.ValueFrom + 1 } }, CancellationToken.None));
        options.MaxProfileRows = 1;
        Assert.Throws<InvalidOperationException>(() => command.Execute(inbound, CancellationToken.None));
        options.MaxProfileRows = 4096;
        options.MaxResponseBytes = 58;
        Assert.Throws<InvalidOperationException>(() => command.Execute(inbound, CancellationToken.None));
        Assert.Throws<OperationCanceledException>(() => command.Execute(inbound, new CancellationToken(true)));
        Assert.False(CustomPullCommandDecoder.TryDecode(inbound.Meter, inbound.Request with { Selector = CustomPullWireSelector.GetWithEntryRange }, out _, out _));
    }

    [Theory]
    [InlineData("3P")]
    [InlineData("CT")]
    public void DifferentTemplateAndReorderedMixedWidthLayoutAreDrivenByMetadata(string category)
    {
        string path = Path.Combine(Path.GetTempPath(), "gr-model-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        try
        {
            File.WriteAllText(Path.Combine(path, "MeterTemplate.csv"), "Id,TemplateName,PushHeaderLength,PullHeaderLength,PushPayloadType,PullPayloadType,IsFG23,BlockTemplateId,MeterProfileHeaderTemplateId\n777,Generated,12,12,2,2,False,888,3\n");
            File.WriteAllText(Path.Combine(path, "MeterTemplateDetail.csv"), $"ProfileTemplateId,ProfileType,SerialNumber,ParameterName,DataType,Scalar,Profile,MeterCategory,CommandTypeId\n888,BLOCK_CUSTOM_PULL_{category},3,RtcDateTime,DateTime,0,2,{category},4\n888,BLOCK_CUSTOM_PULL_{category},1,Status,UInt8,0,2,{category},4\n888,BLOCK_CUSTOM_PULL_{category},2,AverageVoltage,Float32,0,2,{category},4\n");
            var (command, inbound, _, _) = Setup(3, 15, 777, category, path);
            var packet = Assert.Single(command.Execute(inbound, CancellationToken.None));
            Assert.Equal(23 + 2 * 9, packet.Length);
            Assert.Equal(1, packet[23]);
            Assert.Equal(232f, BinaryPrimitives.ReadSingleLittleEndian(packet.AsSpan(24)));
            Assert.Equal(From.AddMinutes(15), DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(28))).AddMinutes(-330));
        }
        finally { Directory.Delete(path, true); }
    }

    private static (CustomProfileCommand Command, CustomPullInbound Inbound, MeterSessionManager Sessions, CustomPullOptions Options) Setup(
        uint mask, int period = 15, int templateId = 93, string category = "1P", string? dataPath = null)
    {
        var registry = new MeterRegistry();
        registry.ImportSnapshot(new BatchStoreSnapshot { NextIndex = 43, NextBatchId = 2,
            Batches = [new PersistedBatch { Id = 1, Name = "gap", StartIndex = 42, Count = 1,
                TemplateName = "unused.xml", NicType = NicType.MqttWirepas, HesTemplateId = templateId, Status = BatchStatus.Running }] });
        var templates = new TemplateRegistry(Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }), new TestEnvironment(), NullLogger<TemplateRegistry>.Instance);
        var sessions = new MeterSessionManager(registry, templates, Options.Create(new BrainOptions()), Options.Create(new TcpOptions()), NullLogger<MeterSessionManager>.Instance);
        var model = new HesDataModelLoader(NullLogger<HesDataModelLoader>.Instance).Load(dataPath ?? Path.Combine(AppContext.BaseDirectory, "Fixtures", "CustomPull"));
        var options = new CustomPullOptions { ProfileDataSource = "Meter", MeterCategories = new() { [templateId] = category }, BlockPeriodMinutesByTemplate = new() { [templateId] = period } };
        var meter = new MeterRef(42, NicType.MqttWirepas);
        var request = new CustomPullRequest(1, 1, 0x12345678, 42, 42, 21, CustomPullWireSelector.GetWithDateRange, 8, (uint)From.AddMinutes(330).ToUnixTimeSeconds(), mask);
        Assert.True(CustomPullCommandDecoder.TryDecode(meter, request, out var intent, out var error), error);
        var inbound = new CustomPullInbound(meter, Assert.Single(registry.Batches), new(templateId, CustomPullWireProfile.NewHeader, 1050946), request, intent);
        return (new(sessions, model, Options.Create(options)), inbound, sessions, options);
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Test";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
