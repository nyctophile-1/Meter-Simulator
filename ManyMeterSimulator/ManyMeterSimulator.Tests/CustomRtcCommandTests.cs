using System.Buffers.Binary;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.SmartNic;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.FileProviders;
using ProtoBuf;

namespace ManyMeterSimulator.Tests;

public class CustomRtcCommandTests
{
    [Fact]
    public void ParsedGetRtc_ReadsTheBrain_AndProducesEndpoint13Response()
    {
        var registry = new MeterRegistry();
        registry.ImportSnapshot(new BatchStoreSnapshot
        {
            NextIndex = 43, NextBatchId = 2,
            Batches = [new PersistedBatch { Id = 1, Name = "rtc", StartIndex = 42, Count = 1,
                TemplateName = "SA1231166HP_values.xml", NicType = NicType.MqttWirepas, HesTemplateId = 41,
                Status = BatchStatus.Running }]
        });
        string folder = Path.Combine(Path.GetTempPath(), "rtc-metadata-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            File.WriteAllText(Path.Combine(folder, "MeterTemplate.csv"), "Id,TemplateName,PushHeaderLength,PullHeaderLength,IsFG23\n41,rtc,10,10,0\n");
            var model = new HesDataModelLoader(NullLogger<HesDataModelLoader>.Instance).Load(folder);
            var ingress = new CustomPullIngress(registry, new CustomPullProtocolResolver(model));
            // Literal HES legacy packet: length, fragments, frame, from/to node, command, selector, data.
            byte[] request = Convert.FromHexString("160101CDAB2A00002A00003001000000000000000000");
            var decoded = ingress.Decode(new MeterRef(42, NicType.MqttWirepas), request);
            Assert.True(decoded.IsComplete, decoded.Detail);
            var templates = new TemplateRegistry(Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
                new TestEnvironment(), NullLogger<TemplateRegistry>.Instance);
            var sessions = new MeterSessionManager(registry, templates, Options.Create(new BrainOptions()), Options.Create(new TcpOptions()), NullLogger<MeterSessionManager>.Instance);
            var processor = new CustomRtcCommand(sessions);
            byte[] framed = processor.Execute(decoded.Inbound!.Value, CancellationToken.None);
            var publish = WirepasCustomPushEnvelope.Create("test-gw", "sink7", "42", 13, framed);
            Assert.Equal("gw-event/received_data/test-gw/sink7/42/13/13", publish.Topic);
            using var stream = new MemoryStream(publish.Payload);
            var packet = Serializer.Deserialize<GenericMessage>(stream).wirepas.packet_received_event;
            Assert.Equal(13u, packet.source_endpoint);
            Assert.Equal(13u, packet.destination_endpoint);
            Assert.Equal((uint)framed.Length, packet.payload_size);
            Assert.Equal(0xABCD, BinaryPrimitives.ReadUInt16LittleEndian(packet.payload.AsSpan(3)));
            uint epoch = BinaryPrimitives.ReadUInt32LittleEndian(packet.payload.AsSpan(28));
            Assert.InRange(DateTimeOffset.FromUnixTimeSeconds(epoch), DateTimeOffset.UtcNow.AddSeconds(-5), DateTimeOffset.UtcNow.AddSeconds(5));
            registry.TryStop(1);
            Assert.Throws<InvalidOperationException>(() => processor.Execute(decoded.Inbound.Value, CancellationToken.None));
        }
        finally { Directory.Delete(folder, true); }
    }

    [Fact]
    public void ExactEqaGetRtc_UsesSelectedMagicAndPreservesFrame()
    {
        var registry = new MeterRegistry();
        registry.ImportSnapshot(new BatchStoreSnapshot
        {
            NextIndex = 210006, NextBatchId = 2,
            Batches = [new PersistedBatch { Id = 1, Name = "rtc", StartIndex = 210005, Count = 1,
                TemplateName = "SA1231166HP_values.xml", NicType = NicType.MqttWirepas, HesTemplateId = 93,
                Status = BatchStatus.Running }]
        });
        string folder = Path.Combine(Path.GetTempPath(), "rtc-metadata-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            File.WriteAllText(Path.Combine(folder, "MeterTemplate.csv"), "Id,TemplateName,PushHeaderLength,PullHeaderLength,IsFG23\n93,rtc,12,12,0\n");
            File.WriteAllText(Path.Combine(folder, "MagicNumberMapping.csv"), "MagicNumber,TemplateId\n1050946,93\n1116430,93\n");
            var model = new HesDataModelLoader(NullLogger<HesDataModelLoader>.Instance).Load(folder);
            var ingress = new CustomPullIngress(registry, new CustomPullProtocolResolver(model, Options.Create(new CustomPullOptions { ResponseMagicNumbers = new() { [93] = 1050946 } })));
            // Literal HES legacy packet: length, fragments, frame, from/to node, command, selector, data.
            byte[] request = Convert.FromHexString("1C01012715000055340300553403003001000000000000000000B294");
            var decoded = ingress.Decode(new MeterRef(210005, NicType.MqttWirepas), request);
            Assert.True(decoded.IsComplete, decoded.Detail);
            var templates = new TemplateRegistry(Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
                new TestEnvironment(), NullLogger<TemplateRegistry>.Instance);
            var sessions = new MeterSessionManager(registry, templates, Options.Create(new BrainOptions()), Options.Create(new TcpOptions()), NullLogger<MeterSessionManager>.Instance);
            var processor = new CustomRtcCommand(sessions);
            byte[] framed = processor.Execute(decoded.Inbound!.Value, CancellationToken.None);
            var publish = WirepasCustomPushEnvelope.Create("test-gw", "sink7", "210005", 13, framed);
            Assert.Equal("gw-event/received_data/test-gw/sink7/210005/13/13", publish.Topic);
            using var stream = new MemoryStream(publish.Payload);
            var packet = Serializer.Deserialize<GenericMessage>(stream).wirepas.packet_received_event;
            Assert.Equal(13u, packet.source_endpoint);
            Assert.Equal(13u, packet.destination_endpoint);
            Assert.Equal((uint)framed.Length, packet.payload_size);
            Assert.Equal(5415u, BinaryPrimitives.ReadUInt32LittleEndian(packet.payload.AsSpan(8)));
            Assert.Equal(1050946u, BinaryPrimitives.ReadUInt32LittleEndian(packet.payload));
            uint epoch = BinaryPrimitives.ReadUInt32LittleEndian(packet.payload.AsSpan(29));
            Assert.InRange(DateTimeOffset.FromUnixTimeSeconds(epoch), DateTimeOffset.UtcNow.AddSeconds(-5), DateTimeOffset.UtcNow.AddSeconds(5));
            registry.TryStop(1);
            Assert.Throws<InvalidOperationException>(() => processor.Execute(decoded.Inbound.Value, CancellationToken.None));
        }
        finally { Directory.Delete(folder, true); }
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Test";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    [Fact]
    public void IsolatedClockRead_PreservesMeterValuesAndExistingAssociation()
    {
        var meter = new DLMSMeter(42, "1.0.0.0.0.255", 16, 1);
        var original = new DLMSServerSession(meter,
            Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        original.Initialize(true);
        var client = new GXDLMSClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        var aarqReply = new GXReplyData();
        Assert.True(client.GetData(original.HandleRequest(client.AARQRequest()[0]), aarqReply));
        client.ParseAAREResponse(aarqReply.Data);
        meter.SetValue("1.0.1.8.0.255", 123456u);

        DateTime before = DateTime.UtcNow.AddSeconds(-2);
        var isolated = original.CreateReadAssociation();
        {
            GXDateTime time = CustomRtcCommand.ReadClock(isolated, CancellationToken.None);
            Assert.InRange(time.Value.UtcDateTime, before, DateTime.UtcNow.AddSeconds(2));
        }
        Assert.Equal(123456u, meter.GetValue("1.0.1.8.0.255"));
        // The original client can read without another AARQ after custom execution.
        var clock = new GXDLMSClock("0.0.1.0.0.255");
        var reply = new GXReplyData();
        Assert.True(client.GetData(original.HandleRequest(client.Read(clock, 2)[0]), reply));
        Assert.Equal(0, reply.Error);
        Assert.NotNull(reply.Value);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Response_IsConsumedByHesRtcLayout_WithFullFrameCorrelation(bool modern)
    {
        CustomPullInbound inbound = Request(modern);
        var wallTime = new DateTime(2026, 9, 10, 17, 23, 45, DateTimeKind.Utc);
        byte[] packet = CustomRtcCommand.Encode(inbound, new GXDateTime(wallTime));
        // Independent offsets from MQTTSendCustomCommandClient.ParseProfileData/GetRTC.
        int header = modern ? 12 : 10;
        Assert.Equal(packet.Length, modern ? BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(4)) : packet[0]);
        uint frame = modern ? BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(8)) : BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(3));
        Assert.Equal(inbound.Request.FrameId, frame);
        if (modern) Assert.Equal(123u, BinaryPrimitives.ReadUInt32LittleEndian(packet));
        int rtcOffset = header + (modern ? 11 : 12);
        uint prefixRtc = BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(rtcOffset));
        uint resultRtc = BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(rtcOffset + 6));
        Assert.Equal(prefixRtc, resultRtc);
        DateTime parsed = DateTimeOffset.FromUnixTimeSeconds(resultRtc).UtcDateTime.AddMinutes(-330);
        Assert.Equal(wallTime, parsed.AddMinutes(330));
        Assert.Equal(rtcOffset + 10, packet.Length);
    }

    [Fact]
    public void UnknownLegacyLayout_IsNotReportedAsSuccess()
    {
        var inbound = Request(false);
        inbound = inbound with { Protocol = inbound.Protocol with { HesTemplateId = 1 } };
        Assert.Throws<NotSupportedException>(() => CustomRtcCommand.Encode(inbound, new GXDateTime(DateTime.UtcNow)));
    }

    private static CustomPullInbound Request(bool modern)
    {
        var meter = new MeterRef(42, NicType.MqttWirepas);
        uint frameId = modern ? 0xFEDC1234 : 0xABCDu;
        var request = new CustomPullRequest(1, 1, frameId, 42, 42, 48, CustomPullWireSelector.GetWithoutData, 0, 0, 0);
        Assert.True(CustomPullCommandDecoder.TryDecode(meter, request, out var intent, out _));
        return new CustomPullInbound(meter, new MeterBatch { Id = 1, Name = "rtc", TemplateName = "meter.xml", StartIndex = 42, Count = 1 },
            new CustomPullProtocolProfile(41, modern ? CustomPullWireProfile.NewHeader : CustomPullWireProfile.Legacy, modern ? 123u : null), request, intent);
    }
}
