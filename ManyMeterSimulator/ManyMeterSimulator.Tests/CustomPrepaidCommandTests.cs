using System.Buffers.Binary;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.SmartNic;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public class CustomPrepaidCommandTests
{
    [Fact]
    public void TransparentDlms_ExposesBothObisFamiliesAndMirrorsWrites()
    {
        var meter = new DLMSMeter(42, "1.0.0.0.0.255", 16, 1);
        var server = new DLMSServerSession(meter,
            Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        server.Initialize(true);
        try
        {
            foreach (int suffix in new[] { 21, 22, 23, 24, 25 })
            {
                Assert.NotNull(meter.GetValue($"0.0.94.96.{suffix}.255"));
                Assert.NotNull(meter.GetValue($"0.0.94.91.{suffix}.255"));
            }
            foreach (int suffix in new[] { 21, 23, 24 })
                Assert.NotEqual(0, Convert.ToInt32(meter.GetValue($"0.0.94.96.{suffix}.255")));
            foreach (int suffix in new[] { 22, 25 })
            {
                var wrapper = Assert.IsType<GXDateTime>(meter.GetValue($"0.0.94.96.{suffix}.255"));
                var hdlc = Assert.IsType<GXDateTime>(meter.GetValue($"0.0.94.91.{suffix}.255"));
                DateTimeSkips required = DateTimeSkips.Year | DateTimeSkips.Month | DateTimeSkips.Day |
                                         DateTimeSkips.Hour | DateTimeSkips.Minute | DateTimeSkips.Second;
                Assert.Equal(0, (int)(wrapper.Skip & required));
                Assert.Equal(0, (int)(hdlc.Skip & required));
            }

            var client = new GXDLMSClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
            GXReplyData Exchange(byte[][] requests)
            {
                var reply = new GXReplyData();
                foreach (byte[] request in requests)
                {
                    Assert.True(client.GetData(server.HandleRequest(request), reply));
                    Assert.Equal(0, reply.Error);
                }
                return reply;
            }
            client.ParseAAREResponse(Exchange(client.AARQRequest()).Data);
            var balance = new GXDLMSData("0.0.94.91.24.255") { Value = 4321 };
            balance.SetDataType(2, DataType.Int32);
            Exchange(client.Write(balance, 2));
            Assert.Equal(4321, Convert.ToInt32(meter.GetValue("0.0.94.91.24.255")));
            Assert.Equal(4321, Convert.ToInt32(meter.GetValue("0.0.94.96.24.255")));
        }
        finally { server.Reset(); }
    }

    [Fact]
    public void TransparentDlms_ReplacesPkg9StyleZeroByteDates()
    {
        string source = Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml");
        string folder = Path.Combine(Path.GetTempPath(), $"maya-prepaid-{Guid.NewGuid():N}");
        Directory.CreateDirectory(folder);
        string template = Path.Combine(folder, "PKG9-zero-byte-dates.xml");
        const string wildcard = "<Value Type=\"9\" UIType=\"25\">*/*/* 00:00:00</Value>";
        const string zeroBytes = "<Value Type=\"9\">00 00 00 00 00 00 00 00 00 00 00 00</Value>";
        File.WriteAllText(template, File.ReadAllText(source).Replace(wildcard, zeroBytes));

        var meter = new DLMSMeter(42, "1.0.0.0.0.255", 16, 1);
        var server = new DLMSServerSession(meter, template);
        server.Initialize(true);
        try
        {
            foreach (int suffix in new[] { 22, 25 })
            {
                var value = Assert.IsType<GXDateTime>(meter.GetValue($"0.0.94.96.{suffix}.255"));
                DateTimeSkips required = DateTimeSkips.Year | DateTimeSkips.Month | DateTimeSkips.Day |
                                         DateTimeSkips.Hour | DateTimeSkips.Minute | DateTimeSkips.Second;
                Assert.Equal(0, (int)(value.Skip & required));
            }
        }
        finally
        {
            server.Reset();
            Directory.Delete(folder, true);
        }
    }

    [Fact]
    public void Command70_ReadsMeterAndReturnsOneHesCompatiblePacket()
    {
        var registry = Registry();
        var templates = new TemplateRegistry(
            Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
            new TestEnvironment(), NullLogger<TemplateRegistry>.Instance);
        var sessions = new MeterSessionManager(registry, templates, Options.Create(new BrainOptions()),
            Options.Create(new TcpOptions()), NullLogger<MeterSessionManager>.Instance);
        var model = new HesDataModelLoader(NullLogger<HesDataModelLoader>.Instance)
            .Load(Path.Combine(AppContext.BaseDirectory, "Fixtures", "CustomPull"));
        var options = new CustomPullOptions { MeterCategories = new() { [93] = "1P" } };
        var meter = new MeterRef(42, NicType.MqttWirepas);
        DLMSServerSession source = sessions.GetOrCreate(meter);
        var lastRecharge = new GXDateTime(new DateTime(2026, 9, 20, 10, 30, 0, DateTimeKind.Utc));
        var balanceTime = new GXDateTime(new DateTime(2026, 9, 23, 12, 45, 0, DateTimeKind.Utc));
        source.Meter.SetValue("0.0.94.96.21.255", 1250);
        source.Meter.SetValue("0.0.94.96.22.255", lastRecharge);
        source.Meter.SetValue("0.0.94.96.23.255", 5000);
        source.Meter.SetValue("0.0.94.96.24.255", -375);
        source.Meter.SetValue("0.0.94.96.25.255", balanceTime);

        CustomPullInbound inbound = Request(registry, meter);
        byte[] packet = new CustomPrepaidCommand(sessions, model, Options.Create(options))
            .Execute(inbound, CancellationToken.None);

        Assert.Equal(49, packet.Length);
        Assert.Equal(1050946u, BinaryPrimitives.ReadUInt32LittleEndian(packet));
        Assert.Equal((ushort)packet.Length, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(4)));
        Assert.Equal(5415u, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(8)));
        Assert.Equal((byte)70, packet[12]);
        Assert.Equal((byte)1, packet[13]);
        Assert.Equal(42u, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(16)));
        uint rtcPrefix = BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(23));
        Assert.Equal((byte)4, packet[27]);
        Assert.Equal((byte)6, packet[28]);
        Assert.Equal(1250, BinaryPrimitives.ReadInt32LittleEndian(packet.AsSpan(29)));
        Assert.Equal(Epoch(lastRecharge), BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(33)));
        Assert.Equal(5000, BinaryPrimitives.ReadInt32LittleEndian(packet.AsSpan(37)));
        Assert.Equal(-375, BinaryPrimitives.ReadInt32LittleEndian(packet.AsSpan(41)));
        Assert.Equal(Epoch(balanceTime), BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(45)));
    }

    [Fact]
    public void Command70_SeedsEmptyTemplateValuesBeforeBuildingResponse()
    {
        var registry = Registry();
        var templates = new TemplateRegistry(
            Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
            new TestEnvironment(), NullLogger<TemplateRegistry>.Instance);
        var sessions = new MeterSessionManager(registry, templates, Options.Create(new BrainOptions()),
            Options.Create(new TcpOptions()), NullLogger<MeterSessionManager>.Instance);
        var model = new HesDataModelLoader(NullLogger<HesDataModelLoader>.Instance)
            .Load(Path.Combine(AppContext.BaseDirectory, "Fixtures", "CustomPull"));
        var options = new CustomPullOptions { MeterCategories = new() { [93] = "1P" } };
        var meter = new MeterRef(42, NicType.MqttWirepas);

        byte[] packet = new CustomPrepaidCommand(sessions, model, Options.Create(options))
            .Execute(Request(registry, meter), CancellationToken.None);

        Assert.Equal(49, packet.Length);
        Assert.NotEqual(0, BinaryPrimitives.ReadInt32LittleEndian(packet.AsSpan(29)));
        Assert.NotEqual(0u, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(33)));
        Assert.NotEqual(0, BinaryPrimitives.ReadInt32LittleEndian(packet.AsSpan(37)));
        Assert.NotEqual(0, BinaryPrimitives.ReadInt32LittleEndian(packet.AsSpan(41)));
        Assert.NotEqual(0u, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(45)));
    }

    [Fact]
    public void EncoderRejectsWildcardTimesBeforePublishing()
    {
        CustomPullInbound inbound = Request(Registry(), new MeterRef(42, NicType.MqttWirepas));
        var wildcard = new GXDateTime { Skip = DateTimeSkips.Year | DateTimeSkips.Month | DateTimeSkips.Day };
        Assert.Throws<InvalidDataException>(() => CustomPrepaidCommand.Encode(
            inbound, wildcard, 1, new GXDateTime(DateTime.UtcNow), 2, 3, new GXDateTime(DateTime.UtcNow)));
    }

    private static MeterRegistry Registry()
    {
        var registry = new MeterRegistry();
        registry.ImportSnapshot(new BatchStoreSnapshot
        {
            NextIndex = 43,
            NextBatchId = 2,
            Batches = [new PersistedBatch { Id = 1, Name = "prepaid", StartIndex = 42, Count = 1,
                TemplateName = "SA1231166HP_values.xml", NicType = NicType.MqttWirepas,
                HesTemplateId = 93, Status = BatchStatus.Running }]
        });
        return registry;
    }

    private static CustomPullInbound Request(MeterRegistry registry, MeterRef meter)
    {
        var request = new CustomPullRequest(1, 1, 5415, 1000000042, 1000000042, 70,
            CustomPullWireSelector.GetWithoutData, 0, 0, 0);
        Assert.True(CustomPullCommandDecoder.TryDecode(meter, request, out CommandIntent intent, out string error), error);
        return new CustomPullInbound(meter, Assert.Single(registry.Batches),
            new CustomPullProtocolProfile(93, CustomPullWireProfile.NewHeader, 1050946, 3), request, intent);
    }

    private static uint Epoch(GXDateTime value) => checked((uint)new DateTimeOffset(
        DateTime.SpecifyKind(value.Value.DateTime, DateTimeKind.Utc)).ToUnixTimeSeconds());

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Test";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
