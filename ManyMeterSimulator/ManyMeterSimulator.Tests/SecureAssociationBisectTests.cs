using System.Text;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Secure;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Xunit;
using Xunit.Abstractions;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Bisects the Step-4 failure: is the brain rejecting the CLIENT ADDRESS / association, or the
/// CIPHERING? Both look identical from outside — Gurux answers nothing either way — so the only way
/// to separate them is to vary one factor at a time against a locally generated AARQ.
/// </summary>
public class SecureAssociationBisectTests
{
    private readonly ITestOutputHelper _output;

    public SecureAssociationBisectTests(ITestOutputHelper output) => _output = output;

    private static byte[] Key16() => Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");

    private static DLMSServerSession BuildSession()
    {
        var meter = new DLMSMeter(507, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        var session = new DLMSServerSession(
            meter, Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        session.Initialize(true);
        return session;
    }

    private byte[] Probe(string label, GXDLMSClient client)
    {
        DLMSServerSession session = BuildSession();
        byte[][] aarq = client.AARQRequest();

        byte[] reply = session.HandleRequest(aarq[0]) ?? Array.Empty<byte>();

        _output.WriteLine($"{label}");
        _output.WriteLine($"   AARQ  : {Convert.ToHexString(aarq[0])}");
        _output.WriteLine($"   reply : {(reply.Length == 0 ? "(NOTHING)" : Convert.ToHexString(reply))}");
        _output.WriteLine("");
        return reply;
    }

    /// <summary>The known-good baseline: the public client HES uses for Step 1.</summary>
    [Fact]
    public void A_PublicClient16_NoCiphering_IsAnswered()
    {
        byte[] reply = Probe(
            "A: client 0x10, Authentication.None, no ciphering",
            new GXDLMSClient(true, 0x10, 1, Authentication.None, null, InterfaceType.WRAPPER));

        Assert.NotEmpty(reply);
    }

    /// <summary>
    /// Client 0x30 with HLS but NO ciphering. If this is answered, the association and client SAP
    /// are fine and the problem is purely the ciphered PDU.
    /// </summary>
    [Fact]
    public void B_Client48_Hls_NoCiphering()
    {
        byte[] reply = Probe(
            "B: client 0x30, Authentication.High, no ciphering",
            new GXDLMSClient(true, 0x30, 1, Authentication.High, "AAAAAAAAAAAAAAAA", InterfaceType.WRAPPER));

        Assert.NotEmpty(reply);
    }

    /// <summary>Exactly how HES builds its secure client (MQTTSendCommandDirectDLMSClient.cs:185+).</summary>
    [Fact]
    public void C_Client48_Hls_WithCiphering_AsHesBuildsIt()
    {
        var secure = new GXDLMSSecureClient(
            true, 0x30, 1, Authentication.High, "AAAAAAAAAAAAAAAA", InterfaceType.WRAPPER);

        secure.Ciphering.Security = Security.AuthenticationEncryption;
        secure.Ciphering.BlockCipherKey = Key16();
        secure.Ciphering.AuthenticationKey = Key16();
        secure.Ciphering.SystemTitle = Encoding.ASCII.GetBytes("ABCDEFGH");
        secure.Ciphering.InvocationCounter = 0;
        secure.Settings.MaxPduSize = 0xFFFF;
        secure.Settings.MaxServerPDUSize = 0xFFFF;

        byte[] reply = Probe("C: client 0x30, HLS, AuthenticationEncryption (HES's exact shape)", secure);

        Assert.NotEmpty(reply);
    }

    /// <summary>
    /// Same as C, but with the invocation counter the real HES frame carried (0x00003C59 = 15449)
    /// instead of 0. This is the only field that differs between the AARQ we generate — which the
    /// brain answers — and the one captured off the wire, which it ignores.
    /// </summary>
    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(15449u)]        // the real value seen on the wire
    [InlineData(4000000000u)]
    public void D_InvocationCounter_DoesNotDecideWhetherWeAnswer(uint invocationCounter)
    {
        var secure = new GXDLMSSecureClient(
            true, 0x30, 1, Authentication.High, "AAAAAAAAAAAAAAAA", InterfaceType.WRAPPER);

        secure.Ciphering.Security = Security.AuthenticationEncryption;
        secure.Ciphering.BlockCipherKey = Key16();
        secure.Ciphering.AuthenticationKey = Key16();
        secure.Ciphering.SystemTitle = Encoding.ASCII.GetBytes("ABCDEFGH");
        secure.Ciphering.InvocationCounter = invocationCounter;
        secure.Settings.MaxPduSize = 0xFFFF;
        secure.Settings.MaxServerPDUSize = 0xFFFF;

        byte[] reply = Probe($"D: invocation counter = {invocationCounter}", secure);

        Assert.NotEmpty(reply);
    }
}
