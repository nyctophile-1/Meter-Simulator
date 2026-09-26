using System.Text;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Secure;
using MeterSimulator.DLMS;
using MeterSimulator.Fota;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Tests;

public sealed class FotaWireTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "maya-fota-wire-" + Guid.NewGuid().ToString("N"));
    private readonly GXDLMSImageTransfer _image = new(DLMSServerSession.ImageTransferObis) { ImageBlockSize = 32 };
    private bool _mqtt;

    private DLMSServerSession Session(long index = 526, bool enabled = true)
    {
        var session = new DLMSServerSession(new DLMSMeter(index, "1.0.0.0.0.255", 16, 1),
            Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        session.Initialize(true);
        session.Fota = new FotaMeter(new FotaStateStore(_root, new()), index.ToString(),
            () => new FotaSettings { Enabled = enabled, TargetVersion = "MAYA-WIRE-2", BlockSize = 32 }, new());
        return session;
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void AuthenticatedLifecycle_ReadsBitmapActivationInfoAndVersion(bool ciphered, bool mqtt)
    {
        _mqtt = mqtt;
        var session = Session();
        var client = Associate(session, ciphered);
        Assert.Equal(true, Read(session, client, _image, 5));
        Assert.Equal(32U, Read(session, client, _image, 2));
        SendOk(session, client, _image.ImageTransferInitiate(client, new byte[] { 1, 2, 3 }, 65)[0]);
        byte[][] blocks = _image.ImageBlockTransfer(client, new byte[65], out int count);
        Assert.Equal(3, count);
        SendOk(session, client, blocks[2]);
        Assert.Equal("001", Read(session, client, _image, 3).ToString());
        Assert.Equal(0U, Read(session, client, _image, 4));
        SendOk(session, client, blocks[0]);

        session = Session();
        client = Associate(session, ciphered);
        Assert.Equal(1U, Read(session, client, _image, 4));
        blocks = _image.ImageBlockTransfer(client, new byte[65], out count);
        SendOk(session, client, blocks[1]);
        SendOk(session, client, _image.ImageVerify(client)[0]);
        var info = Assert.IsType<GXArray>(Read(session, client, _image, 7));
        Assert.Single(info);
        var fields = Assert.IsType<GXStructure>(info[0]);
        Assert.Equal(65U, fields[0]);
        Assert.Equal(new byte[] { 1, 2, 3 }, fields[1]);
        SendOk(session, client, _image.ImageActivate(client)[0]);
        Assert.Equal((byte)6, Convert.ToByte(Read(session, client, _image, 6)));

        object version = Read(session, client, new GXDLMSData(DLMSServerSession.FirmwareVersionObis), 2);
        Assert.Equal("MAYA-WIRE-2", version is byte[] bytes ? Encoding.UTF8.GetString(bytes) : version.ToString());
        var other = Session(527);
        var otherClient = Associate(other, ciphered);
        Assert.Equal("", Read(other, otherClient, _image, 3).ToString());
        Assert.Equal((byte)0, Convert.ToByte(Read(other, otherClient, _image, 6)));
    }

    [Fact]
    public void PublicActionsDisabledTransferAndScheduledActivationAreDenied()
    {
        var session = Session();
        var client = new GXDLMSClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        var association = Send(session, client, client.AARQRequest()[0]);
        client.ParseAAREResponse(association.Data);
        Assert.NotEqual(0, Send(session, client, _image.ImageTransferInitiate(client, new byte[] { 1 }, 32)[0]).Error);

        session = Session(enabled: false);
        client = Associate(session, false);
        Assert.Equal(false, Read(session, client, _image, 5));
        Assert.NotEqual(0, Send(session, client, _image.ImageTransferInitiate(client, new byte[] { 1 }, 32)[0]).Error);
        var schedule = new GXDLMSActionSchedule("0.0.15.0.2.255")
        {
            ExecutionTime = new[] { new GXDateTime(DateTime.UtcNow.AddHours(1)) }
        };
        Assert.NotEqual(0, Send(session, client, client.Write(schedule, 4)[0]).Error);
        _image.ImageTransferEnabled = true;
        Assert.NotEqual(0, Send(session, client, client.Write(_image, 5)[0]).Error);
    }

    [Fact]
    public void HlsMustCompleteBeforeFirmwareMethods()
    {
        var session = Session();
        var client = new GXDLMSClient(true, 0x30, 1, Authentication.High, "AAAAAAAAAAAAAAAA", InterfaceType.WRAPPER);
        var reply = Send(session, client, client.AARQRequest()[0]);
        client.ParseAAREResponse(reply.Data);
        Assert.Throws<GXDLMSConfirmedServiceError>(() =>
            Send(session, client, _image.ImageTransferInitiate(client, new byte[] { 1 }, 32)[0]));
        Assert.Equal("", session.Fota!.Read(3));
    }

    private GXDLMSClient Associate(DLMSServerSession session, bool ciphered)
    {
        var client = new GXDLMSSecureClient(true, 0x30, 1, Authentication.High, "AAAAAAAAAAAAAAAA", InterfaceType.WRAPPER);
        if (ciphered)
        {
            client.Ciphering.Security = Security.AuthenticationEncryption;
            client.Ciphering.BlockCipherKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
            client.Ciphering.AuthenticationKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
            client.Ciphering.SystemTitle = Encoding.ASCII.GetBytes("FOTATEST");
        }

        var reply = Send(session, client, client.AARQRequest()[0]);
        client.ParseAAREResponse(reply.Data);
        reply = Send(session, client, client.GetApplicationAssociationRequest()[0]);
        Assert.Equal(0, reply.Error);
        client.ParseApplicationAssociationResponse(reply.Data);
        return client;
    }

    private object Read(DLMSServerSession session, GXDLMSClient client, GXDLMSObject target, int attribute)
    {
        GXReplyData reply = Send(session, client, client.Read(target, attribute)[0]);
        Assert.Equal(0, reply.Error);
        return reply.Value;
    }

    private void SendOk(DLMSServerSession session, GXDLMSClient client, byte[] request)
    {
        Assert.Equal(0, Send(session, client, request).Error);
    }

    private GXReplyData Send(DLMSServerSession session, GXDLMSClient client, byte[] request)
    {
        byte[] response;
        if (_mqtt)
        {
            var codec = new ManyMeterSimulator.Networking.Mqtt.Codecs.Mqtt4GCodec(ManyMeterSimulator.Networking.Nic.NicType.Mqtt4G);
            var route = new ManyMeterSimulator.Networking.Mqtt.NicRoute(session.Meter.Index.ToString());
            byte[] wrapped = new byte[request.Length + 6];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(wrapped, (ushort)request.Length);
            wrapped[2] = 1;
            wrapped[3] = 1;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(wrapped.AsSpan(4), 1234);
            request.CopyTo(wrapped, 6);
            var envelope = new ManyMeterSimulator.Networking.Mqtt.NicEnvelope("PollRequest/" + route.NodeId, wrapped, DateTimeOffset.UtcNow);
            var decoded = codec.Decode(envelope, route);
            Assert.True(decoded.IsComplete);
            byte[] raw = session.HandleRequest(decoded.DlmsFrame!)!;
            var publish = Assert.Single(codec.Encode(envelope, route, decoded.FrameId, raw));
            Assert.Equal("PollResponse/" + route.NodeId, publish.Topic);
            Assert.Equal(1234, System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(publish.Payload.AsSpan(4)));
            response = publish.Payload[6..];
        }
        else
        {
            response = session.HandleRequest(request) ?? Array.Empty<byte>();
        }

        Assert.NotEmpty(response);
        var reply = new GXReplyData();
        Assert.True(client.GetData(new GXByteBuffer(response), reply, new GXReplyData()));
        return reply;
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, true);
        }
    }
}
