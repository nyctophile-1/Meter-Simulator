using System.Collections;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Tests;

public class DailyProfileValidationTests
{
    [Theory]
    [InlineData("SA1231166HP_values.xml")]
    [InlineData("SA1231166HP_values_bill.xml")]
    public void DailyPullAndPushFitDrishtiFirstRecordEnergyValidation(string template)
    {
        const decimal energyPerMinute = 0.12m;
        const decimal firstRecordLimit = energyPerMinute * 1440 * 5;
        string path = Path.Combine(AppContext.BaseDirectory, "Templates", template);
        var server = new DLMSServerSession(new DLMSMeter(935, "1.0.0.0.0.255", 16, 1), path);
        server.Initialize(true);

        try
        {
            var profile = Assert.IsType<GXDLMSProfileGeneric>(server.Items.Single(
                item => item.LogicalName == "1.0.99.2.0.255"));
            var client = new GXDLMSClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
            var target = new GXDLMSProfileGeneric(profile.LogicalName);

            foreach (var capture in profile.CaptureObjects)
            {
                target.CaptureObjects.Add(capture);
            }

            GXReplyData Exchange(byte[][] requests)
            {
                var reply = new GXReplyData();

                foreach (byte[] request in requests)
                {
                    Assert.True(client.GetData(new GXByteBuffer(server.HandleRequest(request)), reply));
                    Assert.Equal(0, reply.Error);
                }

                return reply;
            }

            client.ParseAAREResponse(Exchange(client.AARQRequest()).Data);
            var decodedRows = new List<(DateTimeOffset Time, decimal Kwh, decimal Kvah)>();

            for (int index = 0; index < profile.Buffer.Count; index++)
            {
                var reply = Exchange(client.ReadRowsByEntry(target, (uint)index + 1, 1));
                Assert.False(reply.IsMoreData);
                var row = Assert.IsAssignableFrom<IList>(
                    Assert.Single(Assert.IsAssignableFrom<IList>(reply.Value).Cast<object>()));
                decimal kwh = Convert.ToDecimal(row[1]);
                decimal kvah = Convert.ToDecimal(row[2]);

                Assert.InRange(kwh, 0.0001m, firstRecordLimit);
                Assert.InRange(kvah, kwh, firstRecordLimit);
                Assert.Equal(0m, Convert.ToDecimal(row[3]));
                Assert.Equal(0m, Convert.ToDecimal(row[4]));
                decodedRows.Add((Assert.IsType<GXDateTime>(profile.Buffer[index][0]).Value, kwh, kvah));
            }

            var ordered = decodedRows.OrderBy(row => row.Time).ToArray();

            for (int index = 1; index < ordered.Length; index++)
            {
                var before = ordered[index - 1];
                var after = ordered[index];
                decimal allowed = (decimal)(after.Time - before.Time).TotalMinutes * energyPerMinute;

                Assert.InRange(after.Kwh - before.Kwh, 0m, allowed);
                Assert.InRange(after.Kvah - before.Kvah, 0m, allowed);
            }

            object[] push = DailyPushTests.Decode(Assert.Single(
                server.BuildPushPayloads(false, DLMSServerSession.DailyPushLogicalName)));

            Assert.Equal(468.4814m, ordered[^1].Kwh);
            Assert.Equal(488.3597m, ordered[^1].Kvah);
            Assert.Equal(ordered[^1].Kwh, Convert.ToDecimal(push[3]));
            Assert.Equal(ordered[^1].Kvah, Convert.ToDecimal(push[4]));
        }
        finally
        {
            server.Reset();
        }
    }
}
