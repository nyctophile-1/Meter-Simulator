using System.Buffers.Binary;
using System.Text;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Secure;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using ManyMeterSimulator.Networking.CustomPush;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using ProtoBuf;
using Task = System.Threading.Tasks.Task;

namespace ManyMeterSimulator.Tests;

public class EswPushTests
{
    private static readonly string Bits = "1000000110000001" + new string('0', 111) + "1";

    [Fact]
    public void CustomPayloadMatchesHesReaderOffsetsBitOrderAndUtcConversion()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_788_999_997);
        byte[] payload = Template93.BuildEsw(now, Bits);
        Assert.Equal(33, payload.Length);
        Assert.Equal(5, payload[0]);
        Assert.Equal(1, payload[1]);
        Assert.All(payload[2..11], b => Assert.Equal(0, b));
        var decodedRtc = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(11))).AddMinutes(-330);
        Assert.Equal(now, decodedRtc);
        Assert.Equal(new byte[] { 4, 128 }, payload[15..17]);
        Assert.Equal(Bits, string.Concat(payload[17..].Select(b => Convert.ToString(b, 2).PadLeft(8, '0'))));
        Assert.Equal(0x81, payload[17]);
        Assert.Equal(1, payload[^1]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("101")]
    [InlineData(null)]
    public void CustomRejectsMalformedWords(string? bits)
        => Assert.Throws<ArgumentException>(() => Template93.BuildEsw(DateTimeOffset.UtcNow, bits!));

    [Fact]
    public void CustomRejectsNonBinaryWord()
        => Assert.Throws<ArgumentException>(() => Template93.BuildEsw(DateTimeOffset.UtcNow, new string('x', 128)));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DlmsEswDecodesAsFourFlatFieldsAndKeepsMeterValuesSeparate(bool ciphering)
    {
        var (meterA, a) = Session(508);
        var (meterB, b) = Session(509);
        string templateDefault = b.GetEventStatusWord();
        meterA.SetValue(EventStatusWord.LogicalName, new GXBitString(Bits));
        meterB.SetValue(EventStatusWord.LogicalName, new GXBitString(new string('0', 128)));
        foreach (var (session, index, expected) in new[] { (a, 508, Bits), (b, 509, new string('0', 128)), (a, 508, Bits) })
        {
            var payload = Assert.Single(session.BuildPushPayloads(ciphering, EventStatusWord.PushLogicalName));
            var parsed = Decode(payload);
            Assert.Equal(4, parsed.Length);
            Assert.Equal("CRY" + MeterIdentity.Serial(index), parsed[0]);
            Assert.Equal(new byte[] { 0, 4, 25, 9, 0, 255 }, Assert.IsType<byte[]>(parsed[1]));
            Assert.Equal(12, Assert.IsType<byte[]>(parsed[2]).Length);
            Assert.Equal(expected, Assert.IsType<GXBitString>(parsed[3]).ToString());
            Assert.Equal(expected, session.GetEventStatusWord());
        }
        var (_, createdAfterPush) = Session(510);
        Assert.Equal(templateDefault, createdAfterPush.GetEventStatusWord());
    }

    [Theory]
    [InlineData("SA1231166HP_values.xml")]
    [InlineData("SA1231166HP_values_bill.xml")]
    [InlineData("Template-31-D2.xml")]
    [InlineData("SZ0000014HP_Only_Push.xml")]
    public void EswIsDiscoveredAndTemplateDefaultCanBePushed(string template)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Templates", template);
        Assert.Contains(MqttPushProfiles.ReadTemplate(path), p => p.LogicalName == MqttPushProfiles.Esw);
        var (_, session) = Session(512, template);
        Assert.Contains(EventStatusWord.PushLogicalName, session.GetPushSetupLogicalNames());
        var parsed = Decode(Assert.Single(session.BuildPushPayloads(false, EventStatusWord.PushLogicalName)));
        Assert.Equal(session.GetEventStatusWord(), parsed[3].ToString());
    }

    private static (DLMSMeter, DLMSServerSession) Session(long index, string template = "SA1231166HP_values.xml")
    {
        var meter = new DLMSMeter(index, "1.0.0.0.0.255", 16, 1);
        var session = new DLMSServerSession(meter, Path.Combine(AppContext.BaseDirectory, "Templates", template));
        session.Initialize(true);
        return (meter, session);
    }

    private static object[] Decode(byte[] payload)
    {
        var client = new GXDLMSSecureClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        client.Ciphering.Security = Security.Encryption;
        client.Ciphering.BlockCipherKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
        client.Ciphering.AuthenticationKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
        var data = new GXReplyData();
        var notify = new GXReplyData();
        client.GetData(new GXByteBuffer(payload), data, notify);
        return Assert.IsAssignableFrom<IEnumerable<object>>(notify.Value ?? data.Value).ToArray();
    }
}

public partial class MqttPushRunTests
{
    [Fact]
    public async Task ExplicitDlmsAndCustomEswKeepTheirOwnEnvelopesOnTheSameWirepasBatch()
    {
        var fixture = new Fixture(1, template: "SA1231166HP_values.xml", customTemplateId: 702);
        foreach (string profile in new[] { MqttPushProfiles.Esw, MqttPushProfiles.CustomEsw })
        {
            await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request with { PushSetupLogicalName = profile });
            Assert.Equal(1, (await run.SendLiveAsync()).MessagesSent);
        }
        var messages = fixture.Publisher.Messages.ToArray();
        Assert.EndsWith("/1/1", messages[0].Topic);
        Assert.EndsWith("/10/10", messages[1].Topic);
        var dlms = Serializer.Deserialize<GenericMessage>(new MemoryStream(messages[0].Payload)).wirepas.packet_received_event.payload;
        var custom = Serializer.Deserialize<GenericMessage>(new MemoryStream(messages[1].Payload)).wirepas.packet_received_event.payload;
        Assert.Equal(new byte[] { 0, 4, 25, 9, 0, 255 }, Assert.IsType<byte[]>(DailyPushTests.Decode(dlms[5..])[1]));
        Assert.Equal(5, custom[12]);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task CustomEswRunsPublishExpectedProfilesAndLiveStatus(bool prepared, bool all)
    {
        var fixture = new Fixture(2, template: "SA1231166HP_values.xml");
        var request = fixture.Request with { PushSetupLogicalName = all ? null : MqttPushProfiles.CustomEsw };
        await using var run = await fixture.Push.OpenMqttRunAsync(request);
        if (prepared) { await run.PrepareAsync(); Assert.Empty(fixture.Publisher.Messages); await run.FireAsync(); }
        else await run.SendLiveAsync();
        Assert.Equal(all ? 6 : 2, fixture.Publisher.Messages.Count);
        foreach (var group in fixture.Publisher.Messages.GroupBy(m => m.Topic))
        {
            Assert.EndsWith("/10/10", group.Key);
            var packets = group.Select(m => Serializer.Deserialize<GenericMessage>(new MemoryStream(m.Payload))
                .wirepas.packet_received_event.payload).ToArray();
            var esw = Assert.Single(packets, p => p[12] == 5);
            Assert.Equal(45, esw.Length);
            Assert.Equal(45, BinaryPrimitives.ReadUInt16LittleEndian(esw.AsSpan(4)));
            Assert.Equal(Template93.MagicNumber, BinaryPrimitives.ReadUInt32LittleEndian(esw));
            var meter = Enumerable.Range(0, 2).Select(i => new ManyMeterSimulator.Networking.Nic.MeterRef(
                fixture.Batch.StartIndex + i, fixture.Batch.NicType)).Single(m => group.Key.Contains($"/{m.NodeId}/10/10"));
            Assert.Equal(fixture.Sessions.GetOrCreate(meter).GetEventStatusWord(),
                string.Concat(esw[29..].Select(b => Convert.ToString(b, 2).PadLeft(8, '0'))));
            if (all) Assert.Single(packets, p => p[12] == 7);
            if (all) Assert.Single(packets, p => p[12] == 48);
        }
    }
}
