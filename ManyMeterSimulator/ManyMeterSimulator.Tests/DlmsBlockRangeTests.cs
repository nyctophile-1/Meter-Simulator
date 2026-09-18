using System.Collections;
using System.Globalization;
using System.Xml.Linq;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Tests;

public class DlmsBlockRangeTests
{
    [Theory]
    [InlineData(900, false, 0)]
    [InlineData(900, true, 0)]
    [InlineData(1800, false, 0)]
    [InlineData(1800, true, 0)]
    [InlineData(3600, false, 0)]
    [InlineData(3600, true, 0)]
    [InlineData(900, false, 330)]
    [InlineData(900, true, 330)]
    [InlineData(1800, false, 330)]
    [InlineData(1800, true, 330)]
    [InlineData(3600, false, 330)]
    [InlineData(3600, true, 330)]
    public void RangeReadReturnsOnlyAlignedRowsInsideRequestedBounds(int period, bool betweenBoundaries, int requestOffsetMinutes)
    {
        string path = Path.Combine(Path.GetTempPath(), "block-range-" + Guid.NewGuid().ToString("N") + ".xml");
        var xml = XDocument.Load(Path.Combine(AppContext.BaseDirectory, "Templates", "D1_Master.xml"));
        var source = xml.Root!.Elements("GXDLMSProfileGeneric").Single(p => p.Element("LN")!.Value == "1.0.99.1.0.255");
        source.Element("CapturePeriod")!.Value = period.ToString(CultureInfo.InvariantCulture);
        var rows = source.Element("Buffer")!.Elements("Row").ToArray();
        var anchor = DateTime.UtcNow.Date.AddDays(-2).AddHours(12).AddMinutes(7).AddSeconds(37);
        for (int i = 0; i < rows.Length; i++)
            rows[i].Elements("Cell").First().Value = anchor.AddSeconds(-i * period).ToString("MM/dd/yyyy HH:mm:ss", CultureInfo.InvariantCulture);
        DLMSServerSession? server = null;
        try
        {
            xml.Save(path);
            server = new(new DLMSMeter(943, "1.0.0.0.0.255", 16, 1), path);
            server.Initialize(true);
            var profile = (GXDLMSProfileGeneric)server.Items.FindByLN(ObjectType.ProfileGeneric, "1.0.99.1.0.255");
            var latest = ((GXDateTime)profile.Buffer[0][0]).Value.UtcDateTime;
            var endBoundary = new DateTime(latest.Ticks / (period * TimeSpan.TicksPerSecond) * (period * TimeSpan.TicksPerSecond), DateTimeKind.Utc);
            var from = endBoundary.AddSeconds(-7 * period + (betweenBoundaries ? 1 : 0));
            var to = endBoundary.AddSeconds(-period - (betweenBoundaries ? 1 : 0));
            var client = new GXDLMSClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER) { MaxReceivePDUSize = 128 };
            client.ProposedConformance &= ~Conformance.GeneralBlockTransfer;
            int blocks = 0;
            GXReplyData Exchange(byte[][] requests)
            {
                var reply = new GXReplyData();
                foreach (var request in requests)
                {
                    Assert.True(client.GetData(new GXByteBuffer(server.HandleRequest(request)), reply));
                    Assert.Equal(0, reply.Error);
                }
                while (reply.IsMoreData)
                {
                    Assert.True(++blocks < 100);
                    var next = client.ReceiverReady(reply);
                    Assert.True(client.GetData(new GXByteBuffer(server.HandleRequest(next)), reply));
                    Assert.Equal(0, reply.Error);
                }
                return reply;
            }
            client.ParseAAREResponse(Exchange(client.AARQRequest()).Data);
            var requestProfile = new GXDLMSProfileGeneric(profile.LogicalName) { SortObject = profile.SortObject };
            requestProfile.CaptureObjects.AddRange(profile.CaptureObjects);
            GXDateTime RequestTime(DateTime utc) => new(new DateTimeOffset(utc).ToOffset(TimeSpan.FromMinutes(requestOffsetMinutes)));
            var response = Exchange(client.ReadRowsByRange(requestProfile, RequestTime(from), RequestTime(to)));
            var decoded = Assert.IsAssignableFrom<IList>(response.Value).Cast<object>().Select(row =>
            {
                var timestamp = Assert.IsAssignableFrom<IList>(row)[0];
                var rtc = timestamp is GXDateTime time ? time : (GXDateTime)GXDLMSClient.ChangeType((byte[])timestamp!, DataType.DateTime);
                Assert.False(rtc.Skip.HasFlag(DateTimeSkips.Deviation));
                return rtc.Value.UtcDateTime;
            }).ToArray();
            Assert.NotEmpty(decoded);
            Assert.All(decoded, rtc =>
            {
                Assert.InRange(rtc, from, to);
                Assert.Equal(0, rtc.Second);
                Assert.Equal(0, rtc.Ticks % TimeSpan.TicksPerSecond);
                Assert.Contains(rtc.Minute, new[] { 0, 15, 30, 45 });
                Assert.Equal(0, rtc.Ticks % (period * TimeSpan.TicksPerSecond));
            });
            var expected = Enumerable.Range(betweenBoundaries ? 2 : 1, betweenBoundaries ? 5 : 7)
                .Select(slot => endBoundary.AddSeconds(-slot * period)).OrderBy(time => time);
            Assert.Equal(expected, decoded.OrderBy(time => time));
            Assert.True(blocks > 0);
            var empty = Exchange(client.ReadRowsByRange(requestProfile,
                RequestTime(endBoundary.AddDays(1)), RequestTime(endBoundary.AddDays(2))));
            Assert.Empty(Assert.IsAssignableFrom<IList>(empty.Value));
        }
        finally { server?.Reset(); File.Delete(path); }
    }
}
