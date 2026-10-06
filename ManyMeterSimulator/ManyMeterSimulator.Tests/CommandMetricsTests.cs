using System.Text;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Secure;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Nic;
using MeterSimulator.DLMS;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Tests;

public sealed class CommandMetricsTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void BrainCountsSuccessfulOperationsAndExcludesHandshakesErrorsAndIntermediateBlocks(
        bool ciphered, bool generalBlockTransfer)
    {
        var session = new DLMSServerSession(new DLMSMeter(826, "1.0.0.0.0.255", 16, 1),
            Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        session.Initialize(true);
        var client = new GXDLMSSecureClient(true, 0x30, 1, Authentication.High,
            "AAAAAAAAAAAAAAAA", InterfaceType.WRAPPER)
        {
            MaxReceivePDUSize = 128,
        };

        if (!generalBlockTransfer)
        {
            client.ProposedConformance &= ~Conformance.GeneralBlockTransfer;
        }

        if (ciphered)
        {
            client.Ciphering.Security = Security.AuthenticationEncryption;
            client.Ciphering.BlockCipherKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
            client.Ciphering.AuthenticationKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
            client.Ciphering.SystemTitle = Encoding.ASCII.GetBytes("METRTEST");
        }

        GXReplyData Exchange(byte[] request, GXReplyData? reply = null)
        {
            reply ??= new GXReplyData();
            byte[] response = session.HandleRequest(request);
            Assert.NotEmpty(response);
            Assert.True(client.GetData(new GXByteBuffer(response), reply));
            return reply;
        }

        client.ParseAAREResponse(Exchange(client.AARQRequest()[0]).Data);
        client.ParseApplicationAssociationResponse(Exchange(client.GetApplicationAssociationRequest()[0]).Data);
        Assert.Equal(0, session.SuccessfulCommands);

        var clock = new GXDLMSClock("0.0.1.0.0.255");
        Assert.Equal(0, Exchange(client.Read(clock, 2)[0]).Error);
        Assert.Equal(1, session.SuccessfulCommands);

        Assert.NotEqual(0, Exchange(client.Read(new GXDLMSData("0.0.0.99.99.255"), 2)[0]).Error);
        Assert.Equal(1, session.SuccessfulCommands);

        var control = new GXDLMSDisconnectControl("0.0.96.3.10.255");
        Assert.Equal(0, Exchange(control.RemoteDisconnect(client)[0]).Error);
        Assert.Equal(2, session.SuccessfulCommands);

        clock.Time = new GXDateTime(DateTime.Now);
        Assert.NotEqual(0, Exchange(client.Write(clock, 2)[0]).Error);
        Assert.Equal(2, session.SuccessfulCommands);

        var balance = new GXDLMSData("0.0.94.91.24.255") { Value = 4321 };
        balance.SetDataType(2, DataType.Int32);
        Assert.Equal(0, Exchange(client.Write(balance, 2)[0]).Error);
        Assert.Equal(3, session.SuccessfulCommands);

        var profile = new GXDLMSProfileGeneric("1.0.99.2.0.255");
        GXReplyData blocks = Exchange(client.Read(profile, 2)[0]);
        Assert.True(blocks.IsMoreData);
        int exchanges = 1;

        while (blocks.IsMoreData)
        {
            Assert.Equal(3, session.SuccessfulCommands);
            byte[] next = client.ReceiverReady(blocks);
            Exchange(next, blocks);
            Assert.True(++exchanges < 100);
        }

        Assert.Equal(0, blocks.Error);
        Assert.Equal(4, session.SuccessfulCommands);

        var list = new List<KeyValuePair<GXDLMSObject, int>> { new(clock, 2), new(balance, 2) };
        Assert.Equal(0, Exchange(client.ReadList(list)[0]).Error);
        Assert.Equal(5, session.SuccessfulCommands);
        session.Reset();
    }

    [Fact]
    public void FleetAndNicCountersRemainSeparateAndThreadSafe()
    {
        var metrics = new SimulatorMetrics();
        Parallel.For(0, 10000, i =>
        {
            var nic = i % 2 == 0 ? NicType.MqttWirepas : NicType.Tcp4G;
            metrics.RecordExchange(nic, TimeSpan.FromMilliseconds(1));

            if (i % 4 != 0)
            {
                metrics.RecordCommandSucceeded(nic);
            }
        });

        Assert.Equal(10000, metrics.Snapshot(0).TotalExchanges);
        Assert.Equal(7500, metrics.Snapshot(0).TotalSuccessfulCommands);
        Assert.Equal(2500, metrics.Snapshot(NicType.MqttWirepas, 0).TotalSuccessfulCommands);
        Assert.Equal(5000, metrics.Snapshot(NicType.Tcp4G, 0).TotalSuccessfulCommands);
    }

    [Fact]
    public void RateUsesElapsedTimeAndRollingWindowWithoutLifetimeBursts()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DashboardActivitySample Sample(int seconds, long count) =>
            new(now.AddSeconds(seconds), 0, count * 2, 0,
                new Dictionary<NicType, NicActivityTotals>(), count);

        double Rate(params DashboardActivitySample[] samples) =>
            DashboardActivityHistory.PerSecond(samples, s => s.TotalSuccessfulCommands);

        Assert.Equal(0, Rate(Sample(0, 1_000_000)));
        Assert.Equal(2.5, Rate(Sample(0, 1_000_000), Sample(4, 1_000_010)));
        Assert.Equal(0, Rate(Sample(0, 10), Sample(4, 10)));
        Assert.Equal(0, Rate(Sample(0, 10), Sample(4, 0)));
        Assert.Equal(0, Rate(Sample(0, 10), Sample(0, 20)));
        Assert.Equal(1, Rate(Sample(0, 0), Sample(60, 1_000_000), Sample(120, 1_000_060)));
    }
}
