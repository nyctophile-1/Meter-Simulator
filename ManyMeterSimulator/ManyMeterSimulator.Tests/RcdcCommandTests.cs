using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Objects.Enums;
using MeterSimulator.DLMS;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Tests;

public class RcdcCommandTests
{
    private const string DisconnectControlLogicalName = "0.0.96.3.10.255";

    [Fact]
    public void DisconnectAndReconnect_ReturnSuccessAndUpdateRelayState()
    {
        var meter = new DLMSMeter(526, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        var session = BuildSession(meter);
        GXDLMSClient client = Associate(session);
        var disconnectControl = new GXDLMSDisconnectControl(DisconnectControlLogicalName);

        GXReplyData disconnectReply = Send(
            session,
            client,
            disconnectControl.RemoteDisconnect(client)[0]);

        Assert.Equal(0, disconnectReply.Error);
        Assert.Equal(false, Read(session, client, disconnectControl, 2));
        Assert.Equal((byte)ControlState.Disconnected, Convert.ToByte(Read(session, client, disconnectControl, 3)));

        GXReplyData reconnectReply = Send(
            session,
            client,
            disconnectControl.RemoteReconnect(client)[0]);

        Assert.Equal(0, reconnectReply.Error);
        Assert.Equal(true, Read(session, client, disconnectControl, 2));
        Assert.Equal((byte)ControlState.Connected, Convert.ToByte(Read(session, client, disconnectControl, 3)));
    }

    [Fact]
    public void DisconnectState_IsIsolatedPerMeter()
    {
        var firstSession = BuildSession(new DLMSMeter(526, "1.0.0.0.0.255", 16, 1));
        var secondSession = BuildSession(new DLMSMeter(527, "1.0.0.0.0.255", 16, 1));
        GXDLMSClient firstClient = Associate(firstSession);
        GXDLMSClient secondClient = Associate(secondSession);
        var disconnectControl = new GXDLMSDisconnectControl(DisconnectControlLogicalName);

        GXReplyData reply = Send(
            firstSession,
            firstClient,
            disconnectControl.RemoteDisconnect(firstClient)[0]);

        Assert.Equal(0, reply.Error);
        Assert.Equal(false, Read(firstSession, firstClient, disconnectControl, 2));
        Assert.Equal(true, Read(secondSession, secondClient, disconnectControl, 2));
    }

    private static DLMSServerSession BuildSession(DLMSMeter meter)
    {
        var session = new DLMSServerSession(
            meter,
            Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        session.Initialize(true);
        return session;
    }

    private static GXDLMSClient Associate(DLMSServerSession session)
    {
        var client = new GXDLMSClient(
            useLogicalNameReferencing: true,
            clientAddress: 16,
            serverAddress: 1,
            authentication: Authentication.None,
            password: null,
            interfaceType: InterfaceType.WRAPPER);

        GXReplyData reply = Send(session, client, client.AARQRequest()[0]);
        client.ParseAAREResponse(reply.Data);
        return client;
    }

    private static object? Read(
        DLMSServerSession session,
        GXDLMSClient client,
        GXDLMSDisconnectControl disconnectControl,
        int attributeIndex)
    {
        GXReplyData reply = Send(session, client, client.Read(disconnectControl, attributeIndex)[0]);
        Assert.Equal(0, reply.Error);
        return reply.Value;
    }

    private static GXReplyData Send(DLMSServerSession session, GXDLMSClient client, byte[] request)
    {
        byte[] response = session.HandleRequest(request) ?? Array.Empty<byte>();
        Assert.NotEmpty(response);

        var reply = new GXReplyData();
        Assert.True(client.GetData(response, reply));
        return reply;
    }
}
