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
    [InlineData(60, 333)]
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
        var (command, inbound, _, _) = Setup(0x80000001, 15);
        var packet = Assert.Single(command.Execute(inbound, CancellationToken.None));
        Assert.Equal(59, packet.Length);
        Assert.Equal(From.AddMinutes(31 * 15), DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(23))).AddMinutes(-330));
        Assert.Equal(From, DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(41))).AddMinutes(-330));
    }

    [Fact]
    public void EmptyMaskReturnsNoData()
    {
        var (command, inbound, _, _) = Setup(0);
        var packet = Assert.Single(command.Execute(inbound, CancellationToken.None));
        Assert.Equal(23, packet.Length);
        Assert.Equal(100, packet[12]);
        Assert.Equal(0, packet[13]);
    }

    [Theory]
    [InlineData(15, 32, 3)]
    [InlineData(30, 16, 2)]
    [InlineData(60, 8, 1)]
    public void AllOnesOnlyReturnsSlotsWithinEightHours(int period, int expectedRows, int expectedPackets)
    {
        var (command, inbound, _, options) = Setup(uint.MaxValue, period);
        options.MaxProfileRows = expectedRows;
        options.MaxResponseBytes = expectedRows * 18 + expectedPackets * 23;
        var packets = command.Execute(inbound, CancellationToken.None);
        Assert.Equal(expectedPackets, packets.Count);
        var decoded = DecodeUtcRows(packets);
        Assert.Equal(expectedRows, decoded.Length);
        Assert.Equal(Enumerable.Range(0, expectedRows).Select(bit => From.AddMinutes(bit * period)), decoded);
        Assert.All(decoded, timestamp => Assert.True(timestamp < From.AddHours(8)));
    }

    [Theory]
    [InlineData(30, 0xffff0000U)]
    [InlineData(60, 0xffffff00U)]
    public void OnlyTrailingBitsSetReturnsNoData(int period, uint mask)
    {
        var (command, inbound, _, options) = Setup(mask, period);
        options.MaxProfileRows = 0;
        var packet = Assert.Single(command.Execute(inbound, CancellationToken.None));
        Assert.Equal(23, packet.Length);
        Assert.Equal(100, packet[12]);
        Assert.Equal(0, packet[13]);
    }

    [Theory]
    [InlineData(30, 0xffff8005U, 15)]
    [InlineData(60, 0xffffff85U, 7)]
    public void TrailingBitsDoNotShiftSparseSelections(int period, uint mask, int lastBit)
    {
        var (command, inbound, _, options) = Setup(mask, period);
        options.MaxProfileRows = 3;
        var decoded = DecodeUtcRows(command.Execute(inbound, CancellationToken.None));
        Assert.Equal(new[] { From, From.AddMinutes(2 * period), From.AddMinutes(lastBit * period) }, decoded);
    }

    private static DateTimeOffset[] DecodeUtcRows(IReadOnlyList<byte[]> packets) => packets.SelectMany(packet =>
        Enumerable.Range(0, packet[13] & 0x0f).Reverse().Select(row =>
            DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(23 + row * 18))).AddMinutes(-330))).ToArray();

    [Theory]
    [InlineData(0x7fffU, 15, 1)]
    [InlineData(0xffffU, 16, 2)]
    [InlineData(0x7fffffffU, 31, 3)]
    [InlineData(0xffffffffU, 32, 3)]
    [InlineData(0xaaaaaaaaU, 16, 2)]
    public void LargeMasksUseCompleteResponsesWithAllSelectedTimestamps(uint mask, int count, int responseCount)
    {
        var (command, inbound, _, _) = Setup(mask);
        var requestedFrom = new DateTimeOffset(2026, 9, 15, 18, 45, 0, TimeSpan.Zero);
        inbound = inbound with { Intent = inbound.Intent with { ValueFrom = checked((uint)requestedFrom.AddMinutes(330).ToUnixTimeSeconds()) } };
        var packets = command.Execute(inbound, CancellationToken.None);
        Assert.Equal(responseCount, packets.Count);
        var decoded = new List<DateTimeOffset>();
        foreach (var packet in packets)
        {
            Assert.Equal(packet.Length, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(4)));
            Assert.Equal(1, packet[6]);
            Assert.Equal(1, packet[7]);
            Assert.Equal(inbound.Request.FrameId, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(8)));
            Assert.Equal(19, packet[12]);
            int rows = packet[13] & 0x0f;
            Assert.InRange(rows, 1, 15);
            Assert.Equal(0, packet[13] >> 4);
            Assert.Equal(23 + rows * 18, packet.Length);
            for (int row = rows - 1; row >= 0; row--)
                decoded.Add(DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(23 + row * 18))).AddMinutes(-330));
        }
        var expected = Enumerable.Range(0, 32).Where(bit => (mask & (1U << bit)) != 0)
            .Select(bit => requestedFrom.AddMinutes(bit * 15)).ToArray();
        Assert.Equal(count, decoded.Count);
        Assert.Equal(expected, decoded);
    }

    [Fact]
    public void ResponseByteLimitIncludesEveryHeader()
    {
        var (command, inbound, _, options) = Setup(uint.MaxValue);
        options.MaxResponseBytes = 32 * 18 + 3 * 23;
        Assert.Equal(3, command.Execute(inbound, CancellationToken.None).Count);
        options.MaxResponseBytes--;
        Assert.Throws<InvalidOperationException>(() => command.Execute(inbound, CancellationToken.None));
    }

    [Theory]
    [InlineData("11111111111111111111111111111111", "10:45 11:00 11:15 11:30 11:45 12:00 12:15 12:30 12:45 13:00 13:15 13:30 13:45 14:00 14:15 14:30 14:45 15:00 15:15 15:30 15:45 16:00 16:15 16:30 16:45 17:00 17:15 17:30 17:45 18:00 18:15 18:30")]
    [InlineData("11111110001111111111111111111111", "10:45 11:00 11:15 11:30 11:45 12:00 12:15 13:15 13:30 13:45 14:00 14:15 14:30 14:45 15:00 15:15 15:30 15:45 16:00 16:15 16:30 16:45 17:00 17:15 17:30 17:45 18:00 18:15 18:30")]
    [InlineData("00111111111111001111111111011111", "11:15 11:30 11:45 12:00 12:15 12:30 12:45 13:00 13:15 13:30 13:45 14:00 14:45 15:00 15:15 15:30 15:45 16:00 16:15 16:30 16:45 17:00 17:30 17:45 18:00 18:15 18:30")]
    public void ReportedRfCommandsReturnExactUtcSlots(string bits, string expectedTimes)
    {
        uint mask = 0;
        for (int bit = 0; bit < bits.Length; bit++)
            if (bits[bit] == '1') mask |= 1U << bit;
        var (command, inbound, _, _) = Setup(mask);
        var requestedFrom = new DateTimeOffset(2026, 9, 16, 10, 45, 0, TimeSpan.Zero);
        inbound = inbound with { Intent = inbound.Intent with { ValueFrom = checked((uint)requestedFrom.AddMinutes(330).ToUnixTimeSeconds()) } };
        var decoded = command.Execute(inbound, CancellationToken.None).SelectMany(packet =>
            Enumerable.Range(0, packet[13] & 0x0f).Reverse().Select(row =>
                DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(23 + row * 18))).AddMinutes(-330))).ToArray();
        Assert.All(decoded, rtc => Assert.Equal(requestedFrom.Date, rtc.Date));
        Assert.Equal(expectedTimes.Split(' '), decoded.Select(rtc => rtc.ToString("HH:mm")));
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
