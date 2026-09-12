using System.Buffers.Binary;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;

namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>GetRTC only. Uses the meter's supported public read association, isolated from HES.</summary>
public sealed class CustomRtcCommand(MeterSessionManager sessions)
{
    public byte[] Execute(CustomPullInbound inbound, CancellationToken cancellationToken)
    {
        if (inbound.Intent.Command != CustomCommandType.GetRealtimeClock ||
            inbound.Intent.Selector != CustomDataSelector.GetWithoutData)
            throw new NotSupportedException("Only custom GetRTC is implemented.");
        if (inbound.Batch.Status != BatchStatus.Running || inbound.Meter.Nic != NicType.MqttWirepas)
            throw new InvalidOperationException("Custom GetRTC requires a running Wirepas batch.");
        ValidateProfile(inbound.Protocol);
        cancellationToken.ThrowIfCancellationRequested();
        var association = sessions.GetOrCreate(inbound.Meter).CreateReadAssociation();
        try { return Encode(inbound, ReadClock(association, cancellationToken)); }
        finally { association.Reset(); }
    }

    public static GXDateTime ReadClock(DLMSServerSession association, CancellationToken cancellationToken)
    {
        var client = new GXDLMSClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        GXReplyData Exchange(byte[][] requests)
        {
            var reply = new GXReplyData();
            foreach (byte[] request in requests)
            {
                cancellationToken.ThrowIfCancellationRequested();
                byte[] response = association.HandleRequest(request) ?? [];
                if (response.Length == 0 || !client.GetData(response, reply) || reply.Error != 0 || reply.IsMoreData)
                    throw new InvalidOperationException($"Custom RTC DLMS exchange failed ({reply.Error}).");
            }
            return reply;
        }
        try
        {
            client.ParseAAREResponse(Exchange(client.AARQRequest()).Data);
            var clock = new GXDLMSClock("0.0.1.0.0.255");
            GXReplyData value = Exchange(client.Read(clock, 2));
            client.UpdateValue(clock, 2, value.Value);
            return clock.Time ?? throw new InvalidOperationException("Meter returned no RTC.");
        }
        finally
        {
            // The isolated owner resets the association if cancellation prevents release.
            if (!cancellationToken.IsCancellationRequested)
                foreach (byte[] release in client.ReleaseRequest() ?? []) association.HandleRequest(release);
        }
    }

    private static void ValidateProfile(CustomPullProtocolProfile profile)
    {
        // HES ParseProfileData has additional vendor-specific layouts for IDs <= 26.
        // Do not invent their identities/offsets. New-header layout is independent of ID.
        if (profile.WireProfile != CustomPullWireProfile.NewHeader && profile.HesTemplateId <= 26)
            throw new NotSupportedException("Legacy GetRTC requires a verified HES template ID above 26.");
    }

    public static byte[] Encode(CustomPullInbound inbound, GXDateTime clock)
    {
        ValidateProfile(inbound.Protocol);
        bool modern = inbound.Protocol.WireProfile == CustomPullWireProfile.NewHeader;
        if (!modern && MeterNodeIds.Value(inbound.Meter.Index) > 0xFFFFFF)
            throw new NotSupportedException("This legacy HES response layout carries only a 24-bit RF node ID.");
        // HES GetDateTime subtracts 330 minutes; GetRTC adds them back for JsonResponse.Value.
        // Encode the DLMS clock's wall time, not the host timezone's interpretation of it.
        uint seconds = checked((uint)new DateTimeOffset(DateTime.SpecifyKind(clock.Value.DateTime, DateTimeKind.Utc)).ToUnixTimeSeconds());
        byte[] body = new byte[modern ? 21 : 22];
        body[0] = inbound.Intent.RawCommandType;
        if (modern)
        {
            body[1] = 0x01; // low nibble: one row; high nibble: clock status zero
            body[2] = (byte)'M'; body[3] = (byte)'Y';
            // This field is the numeric meter serial, not the RF node address.
            BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(4), checked((uint)inbound.Meter.Index));
        }
        else
        {
            uint node = MeterNodeIds.Value(inbound.Meter.Index);
            body[1] = (byte)node; body[2] = (byte)(node >> 8); body[3] = (byte)(node >> 16);
            body[4] = (byte)'M'; body[5] = (byte)'Y';
            BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(6), checked((uint)inbound.Meter.Index));
            body[11] = 1;
        }
        int at = modern ? 11 : 12;
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(at), seconds);
        body[at + 4] = 4;
        body[at + 5] = 6; // uint32 epoch
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(at + 6), seconds);
        return CustomPushFramer.Frame(body, modern ? CustomPushHeaderKind.New : CustomPushHeaderKind.Old,
            inbound.Request.FrameId, inbound.Protocol.ResponseMagicNumber);
    }
}
