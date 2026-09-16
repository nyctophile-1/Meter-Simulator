using System.Buffers.Binary;
using System.Formats.Asn1;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Tests;

public class DlmsReleaseResponseTests
{
    [Fact]
    public void PublicAssociationReleaseHasValidBerLengthsAfterCounterRead()
    {
        var server = new DLMSServerSession(new DLMSMeter(931, "1.0.0.0.0.255", 16, 1),
            Path.Combine(AppContext.BaseDirectory, "Templates", "D1_Master.xml"));
        server.Initialize(true);
        try
        {
            var client = new GXDLMSClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
            GXReplyData Exchange(byte[][] requests)
            {
                var reply = new GXReplyData();
                foreach (var request in requests)
                {
                    Assert.True(client.GetData(new GXByteBuffer(server.HandleRequest(request)), reply));
                    Assert.Equal(0, reply.Error);
                }
                return reply;
            }
            client.ParseAAREResponse(Exchange(client.AARQRequest()).Data);
            Exchange(client.Read(new GXDLMSData("0.0.43.1.3.255"), 2));
            var response = server.HandleRequest(Assert.Single(client.ReleaseRequest()))!;
            Assert.Equal(response.Length - 8, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6, 2)));
            var reader = new AsnReader(response.AsMemory(8), AsnEncodingRules.BER);
            var release = reader.ReadSequence(new Asn1Tag(TagClass.Application, 3, true));
            Assert.Equal(0, (int)release.ReadInteger(new Asn1Tag(TagClass.ContextSpecific, 0)));
            var information = release.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 30, true));
            Assert.NotEmpty(information.ReadOctetString());
            information.ThrowIfNotEmpty();
            release.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            var parsed = new GXReplyData();
            Assert.True(client.GetData(new GXByteBuffer(response), parsed));
            Assert.Equal(Command.ReleaseResponse, parsed.Command);
        }
        finally { server.Reset(); }
    }
}
