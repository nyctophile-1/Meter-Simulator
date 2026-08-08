using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Xunit;
using Xunit.Abstractions;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Reproduces HES's own client-side handling of our reply, using the same Gurux library HES uses.
///
/// <para>
/// This exists because the remaining failure is invisible from our side of the wire. HES logs
/// "Step 2: Read Request on PublicClient Started" BEFORE it calls
/// <c>publicClient.ParseAAREResponse(...)</c> (MQTTSendCommandDirectDLMSClient.cs:1045-1047), so a
/// throw there produces a "Started" with no "Completed", leaves the command unadvanced, and makes
/// HES resend the identical AARQ on its retry timer — exactly the behaviour observed.
/// </para>
///
/// <para>
/// HES builds its client as
/// <c>ClientFactory.CreateClient(true, 0x10, 1, Authentication.None, null, InterfaceType.WRAPPER)</c>
/// (line 185), which is what is mirrored here.
/// </para>
/// </summary>
public class HesClientParsesOurAareTests
{
    private readonly ITestOutputHelper _output;

    public HesClientParsesOurAareTests(ITestOutputHelper output) => _output = output;

    /// <summary>Exactly how HES constructs the public client for a direct-4G pull.</summary>
    private static GXDLMSClient HesPublicClient() =>
        new(true, 0x10, 1, Authentication.None, null, InterfaceType.WRAPPER);

    [Fact]
    public void HesClient_ParsesOurAare_WithoutThrowing()
    {
        GXDLMSClient client = HesPublicClient();

        // HES sends this first; the client must be in the post-AARQ state before it can parse an
        // AARE, exactly as in the live flow.
        byte[][] aarq = client.AARQRequest();
        _output.WriteLine($"AARQ built by a HES-shaped client: {Convert.ToHexString(aarq[0])}");

        // Our real reply, taken off the wire (PollResponse/537), NIC header already stripped.
        byte[] ourAareFrame = Convert.FromHexString(
            "000100010010002B" +
            "6129A109060760857405080101A203020100A305A103020100BE10040E0800065F1F0400621E5DFFFF0007");

        var reply = new GXReplyData();
        client.GetData(ourAareFrame, reply);

        _output.WriteLine($"reply.Command = {reply.Command}");
        _output.WriteLine($"reply.Data    = {Convert.ToHexString(reply.Data.Data, 0, reply.Data.Size)}");

        // This is HES line 1047. If it throws, HES never reaches "Step 2 Completed".
        Exception? thrown = Record.Exception(() => client.ParseAAREResponse(reply.Data));

        if (thrown is not null)
        {
            _output.WriteLine($"ParseAAREResponse THREW: {thrown.GetType().Name}: {thrown.Message}");
        }

        Assert.Null(thrown);
    }

    /// <summary>
    /// The AARQ a HES-shaped client generates must match the one we actually received, or the
    /// client here is not the client HES is running and nothing else in this file means anything.
    /// </summary>
    [Fact]
    public void OurCapturedRequest_MatchesWhatAHesShapedClientProduces()
    {
        byte[][] aarq = HesPublicClient().AARQRequest();

        byte[] captured = Convert.FromHexString(
            "00010010000100" + "1F" +
            "601DA109060760857405080101BE10040E01000000065F1F0400621E5DFFFF");

        _output.WriteLine($"generated: {Convert.ToHexString(aarq[0])}");
        _output.WriteLine($"captured : {Convert.ToHexString(captured)}");

        Assert.Equal(Convert.ToHexString(captured), Convert.ToHexString(aarq[0]));
    }

    /// <summary>
    /// The client SAPs on our two associations must equal the client addresses HES actually dials.
    ///
    /// <para>
    /// HES uses <c>0x10</c> for the public client and <c>0x30</c> for the ciphered HLS client
    /// (<c>CreateClient(true, 0x10, …)</c> / <c>CreateSecureClient(true, 0x30, …, HLSUSSecret, …)</c>).
    /// Those are 16 and 48 in decimal. They were once written as 10 and 30 — the hex digits typed as
    /// decimal — which cost a full debugging session: the public association still answered because
    /// <c>IsTarget</c> accepts any address, but the HLS association could never be matched for client
    /// 48, so the secure AARQ went unanswered and every HES pull stalled after its Step 4 with no
    /// error on either side.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("0.0.40.0.1.255", 16)]   // public client, 0x10
    [InlineData("0.0.40.0.0.255", 48)]   // US/HLS client, 0x30
    public void AssociationClientSaps_MatchTheAddressesHesDials(string logicalName, int expectedSap)
    {
        var meter = new DLMSMeter(526, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        var session = new DLMSServerSession(
            meter, Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        session.Initialize(true);

        var association = session.Items.FindByLN(ObjectType.AssociationLogicalName, logicalName)
            as GXDLMSAssociationLogicalName;

        Assert.NotNull(association);
        _output.WriteLine($"{logicalName} ClientSAP = {association!.ClientSAP} (expected {expectedSap})");
        Assert.Equal(expectedSap, association.ClientSAP);
    }

    /// <summary>
    /// What HES holds after parsing our AARE. If authentication were required, or the negotiated
    /// conformance excluded the services the next step uses, HES would stall right here with no
    /// error to log.
    /// </summary>
    [Fact]
    public void AfterParsingOurAare_TheClientIsReadyToRead()
    {
        GXDLMSClient client = HesPublicClient();
        client.AARQRequest();

        var reply = new GXReplyData();
        client.GetData(
            Convert.FromHexString(
                "000100010010002B" +
                "6129A109060760857405080101A203020100A305A103020100BE10040E0800065F1F0400621E5DFFFF0007"),
            reply);

        client.ParseAAREResponse(reply.Data);

        _output.WriteLine($"IsAuthenticationRequired = {client.IsAuthenticationRequired}");
        _output.WriteLine($"NegotiatedConformance    = {client.NegotiatedConformance}");
        _output.WriteLine($"MaxReceivePDUSize        = {client.MaxReceivePDUSize}");

        // A public/None-authentication association must not ask for a challenge — if it did, HES
        // would go down the secure-client branch and never send the read.
        Assert.False(client.IsAuthenticationRequired);

        // The very next thing HES does is a GET; without this bit the client cannot form one.
        Assert.True(client.NegotiatedConformance.HasFlag(Conformance.Get));
    }
}
