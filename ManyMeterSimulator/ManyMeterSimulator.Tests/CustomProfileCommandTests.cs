using System.Buffers.Binary;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.SmartNic;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public class CustomProfileCommandTests
{
    [Theory]
    [InlineData(3, 22)] [InlineData(4, 19)] [InlineData(5, 20)] [InlineData(6, 21)]
    [InlineData(41, 23)] [InlineData(42, 24)] [InlineData(43, 25)] [InlineData(44, 26)]
    [InlineData(45, 27)] [InlineData(46, 28)] [InlineData(47, 29)] [InlineData(50, 22)] [InlineData(83, 83)]
    public void AllProfiles_GenerateUsingExportedEqaLayout(byte command, byte responseType)
    {
        var registry = new MeterRegistry();
        registry.ImportSnapshot(new BatchStoreSnapshot { NextIndex = 43, NextBatchId = 2,
            Batches = [new PersistedBatch { Id = 1, Name = "profiles", StartIndex = 42, Count = 1,
                TemplateName = "SA1231166HP_values.xml", NicType = NicType.MqttWirepas, HesTemplateId = 93, Status = BatchStatus.Running }] });
        var environment = new TestEnvironment();
        var templates = new TemplateRegistry(Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }), environment, NullLogger<TemplateRegistry>.Instance);
        var sessions = new MeterSessionManager(registry, templates, Options.Create(new BrainOptions()), Options.Create(new TcpOptions()), NullLogger<MeterSessionManager>.Instance);
        var model = new HesDataModelLoader(NullLogger<HesDataModelLoader>.Instance).Load(Path.Combine(AppContext.BaseDirectory, "Fixtures", "CustomPull"));
        var options = new CustomPullOptions { MeterCategories = new() { [93] = "1P" }, EventsWithPowerProfile = [1,2,3,4,5,6,7,8,9,10,11,12,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,81,82,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,887,888,889,890,891,892] };
        var meter = new MeterRef(42, NicType.MqttWirepas);
        var batch = Assert.Single(registry.Batches);
        var request = new CustomPullRequest(1, 1, 5415, 42, 42, command,
            command == 3 ? CustomPullWireSelector.GetWithoutData : CustomPullWireSelector.GetWithEntryRange, command == 3 ? (byte)0 : (byte)8, 1, 1);
        Assert.True(CustomPullCommandDecoder.TryDecode(meter, request, out var intent, out var error), error);
        var inbound = new CustomPullInbound(meter, batch!, new(93, CustomPullWireProfile.NewHeader, 1050946), request, intent);
        var packets = new CustomProfileCommand(sessions, model, Options.Create(options)).Execute(inbound, CancellationToken.None);
        var packet = Assert.Single(packets);
        Assert.Equal(responseType, packet[12]);
        Assert.Equal(1, packet[13]);
        Assert.Equal(5415u, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(8)));
        Assert.Equal(packet.Length, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(4)));
        Assert.True(packet.Length > 23);
        int expectedDataBytes = command switch { 3 or 50 => 70, 4 => 18, 5 => 20, 6 => 85, 41 or 42 or 45 or 83 => 23, _ => 6 };
        Assert.Equal(23 + expectedDataBytes, packet.Length);
        var publish = WirepasCustomPushEnvelope.Create("direct_4g", "direct_4g", "42", 13, packet);
        Assert.Equal("gw-event/received_data/direct_4g/direct_4g/42/13/13", publish.Topic);
    }

    [Fact]
    public void ScalerAndEngineeringUnitsAreAppliedExactlyOnce()
    {
        var field = new TemplateField(1, "CumulativeEnergyKwhImport", "UInt16", -3, 2, "1P", 4);
        var register = new GXDLMSRegister("1.0.1.29.0.255") { Scaler = 0.01, Unit = Unit.ActiveEnergy };
        Assert.Equal(1234, BinaryPrimitives.ReadUInt16LittleEndian(CustomProfileCommand.EncodeField(field, 123400, register, 330)));
        Assert.Throws<OverflowException>(() => CustomProfileCommand.EncodeField(field, 9000000, register, 330));
        var rtc = field with { ParameterName = "RtcDateTime", DataType = "DateTime", Scalar = 0 };
        DateTime date = new(2026, 9, 10, 12, 0, 0, DateTimeKind.Utc);
        uint epoch = BinaryPrimitives.ReadUInt32LittleEndian(CustomProfileCommand.EncodeField(rtc, new GXDateTime(date), new GXDLMSClock(), 330));
        Assert.Equal(date, DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime.AddMinutes(-330));
    }

    [Fact]
    public void EntryRangesAreInclusiveAndBounded()
    {
        Assert.Equal((2u, 3u), CustomProfileCommand.SelectEntries(10, CustomDataSelector.GetWithEntryRange, 2, 4));
        Assert.Equal((7u, 3u), CustomProfileCommand.SelectEntries(10, CustomDataSelector.GetLatestEntriesRange, 2, 4));
        Assert.Equal((1u, 0u), CustomProfileCommand.SelectEntries(10, CustomDataSelector.GetWithEntryRange, 11, 20));
        Assert.Throws<ArgumentException>(() => CustomProfileCommand.SelectEntries(10, CustomDataSelector.GetWithEntryRange, 4, 2));
    }

    [Fact]
    public void GeneratedHistoryHonorsDatesLatestEntriesAndLimits()
    {
        var now = new DateTimeOffset(2026, 9, 10, 12, 0, 0, TimeSpan.Zero);
        var options = new CustomPullOptions();
        var intent = new CommandIntent(new(42, NicType.MqttWirepas), CustomCommandType.GetBlockLoadProfile,
            CustomDataSelector.GetLatestEntriesRange, 4, 1, 3);
        var latest = CustomProfileDataGenerator.SelectTimestamps(intent, now, options);
        Assert.Equal(new[] { now.AddMinutes(-30), now.AddMinutes(-15), now }, latest);
        var range = intent with { Selector = CustomDataSelector.GetWithDateRange,
            ValueFrom = (uint)now.AddMinutes(330 - 30).ToUnixTimeSeconds(), ValueTo = (uint)now.AddMinutes(330).ToUnixTimeSeconds() };
        Assert.Equal(latest, CustomProfileDataGenerator.SelectTimestamps(range, now, options));
        Assert.Empty(CustomProfileDataGenerator.SelectTimestamps(range with { ValueFrom = (uint)now.AddDays(1).ToUnixTimeSeconds(), ValueTo = (uint)now.AddDays(2).ToUnixTimeSeconds() }, now, options));
        options.MaxProfileRows = 2;
        Assert.Throws<InvalidOperationException>(() => CustomProfileDataGenerator.SelectTimestamps(intent, now, options));
    }

    [Fact]
    public void GeneratedValuesRepeatAndCumulativeEnergyIncreasesWithTime()
    {
        var field = new TemplateField(1, "CumulativeEnergyKwhImport", "UInt32", -3, 3, "1P", 5);
        var date = new DateTimeOffset(2026, 9, 10, 0, 0, 0, TimeSpan.Zero);
        object first = CustomProfileDataGenerator.Value(field, 42, date, "DAILY", 0);
        Assert.Equal(first, CustomProfileDataGenerator.Value(field, 42, date, "DAILY", 0));
        Assert.NotEqual(first, CustomProfileDataGenerator.Value(field, 43, date, "DAILY", 0));
        Assert.Equal((decimal)first + 8m, CustomProfileDataGenerator.Value(field, 42, date.AddDays(1), "DAILY", 0));
    }

    [Fact]
    public void LegacyFragmentationPreservesEveryByteAndCorrelation()
    {
        var meter = new MeterRef(42, NicType.MqttWirepas);
        var request = new CustomPullRequest(1, 1, 1234, 42, 42, 6, CustomPullWireSelector.GetWithoutData, 0, 0, 0);
        Assert.True(CustomPullCommandDecoder.TryDecode(meter, request, out var intent, out _));
        var inbound = new CustomPullInbound(meter, new MeterBatch { Id = 1, Name = "test", TemplateName = "unused", StartIndex = 42, Count = 1 }, new(41, CustomPullWireProfile.Legacy, null), request, intent);
        byte[] body = Enumerable.Range(0, 500).Select(i => (byte)i).ToArray();
        var packets = CustomProfileCommand.Frame(inbound, body);
        Assert.Equal(3, packets.Count);
        Assert.Equal(body, packets.SelectMany(p => p.Skip(10)).ToArray());
        for (int i = 0; i < packets.Count; i++)
        {
            Assert.Equal(packets[i].Length, packets[i][0]);
            Assert.Equal(3, packets[i][1]); Assert.Equal(i + 1, packets[i][2]);
            Assert.Equal(1234, BinaryPrimitives.ReadUInt16LittleEndian(packets[i].AsSpan(3)));
        }
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Test";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
