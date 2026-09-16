using System.Collections;
using System.Globalization;
using System.Xml.Linq;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Tests;

public class D1MasterTemplateTests
{
    static string Template(string name) => Path.Combine(AppContext.BaseDirectory, "Templates", name);

    [Fact]
    public void MasterPreservesBaseModelAndExactBillingRows()
    {
        var baseline = XDocument.Load(Template("SA1231166HP_values.xml"));
        var master = XDocument.Load(Template("D1_Master.xml"));
        var donor = XDocument.Load(Template("SA1231166HP_values_bill.xml"));
        XElement Billing(XDocument doc) => doc.Root!.Elements("GXDLMSProfileGeneric")
            .Single(p => (string?)p.Element("LN") == "1.0.98.1.0.255");
        Assert.True(XNode.DeepEquals(Billing(donor).Element("Buffer"), Billing(master).Element("Buffer")));
        foreach (var doc in new[] { baseline, master })
        {
            doc.DescendantNodes().OfType<XComment>().Remove();
            foreach (var profile in doc.Root!.Elements("GXDLMSProfileGeneric"))
            {
                profile.Element("Buffer")?.Remove();
                profile.Element("EntriesInUse")?.Remove();
            }
        }
        XElement Normalize(XElement node) => new(node.Name,
            node.Attributes().Select(a => new XAttribute(a)),
            node.HasElements ? node.Elements().Select(Normalize) : node.Value);
        Assert.True(XNode.DeepEquals(Normalize(baseline.Root!), Normalize(master.Root!)));
    }

    [Theory]
    [InlineData("0.0.99.98.0.255", 13)]
    [InlineData("0.0.99.98.2.255", 13)]
    [InlineData("0.0.99.98.3.255", 1)]
    [InlineData("0.0.99.98.4.255", 12)]
    public void CapturedEventRowsRoundTripWithOriginalColumns(string logicalName, int expectedRows)
    {
        var server = new DLMSServerSession(new DLMSMeter(928, "1.0.0.0.0.255", 16, 1), Template("D1_Master.xml"));
        server.Initialize(true);
        try
        {
            var profile = Assert.IsType<GXDLMSProfileGeneric>(server.Items.Single(o => o.LogicalName == logicalName));
            Assert.Equal(expectedRows, profile.Buffer.Count);
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
            var target = new GXDLMSProfileGeneric(logicalName);
            foreach (var capture in profile.CaptureObjects) target.CaptureObjects.Add(capture);
            var reply = Exchange(client.ReadRowsByEntry(target, 1, 1));
            Assert.False(reply.IsMoreData);
            var row = Assert.IsAssignableFrom<IList>(Assert.Single(Assert.IsAssignableFrom<IList>(reply.Value).Cast<object>()));
            Assert.Equal(profile.CaptureObjects.Count, row.Count);
            for (int column = 1; column < row.Count; column++)
                Assert.Equal(Convert.ToDouble(profile.Buffer[0][column], CultureInfo.InvariantCulture),
                    Convert.ToDouble(row[column], CultureInfo.InvariantCulture));
        }
        finally { server.Reset(); }
    }

    [Theory]
    [InlineData("en-IN")]
    [InlineData("en-US")]
    [InlineData("fr-FR")]
    public void BillingReadsAndUtcRecencyDoNotDependOnHostCulture(string cultureName)
    {
        var previous = CultureInfo.CurrentCulture;
        string path = Path.Combine(Path.GetTempPath(), "d1-master-" + Guid.NewGuid().ToString("N") + ".xml");
        File.Copy(Template("D1_Master.xml"), path);
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
            var before = DateTimeOffset.UtcNow.AddSeconds(-2);
            var server = new DLMSServerSession(new DLMSMeter(927, "1.0.0.0.0.255", 16, 1), path);
            server.Initialize(true);
            var profile = Assert.IsType<GXDLMSProfileGeneric>(server.Items.Single(o => o.LogicalName == "1.0.98.1.0.255"));
            Assert.Equal(13, profile.Buffer.Count);
            var dates = profile.Buffer.Select(row => Assert.IsType<GXDateTime>(row[0]).Value).ToArray();
            Assert.All(dates, time => Assert.Equal(TimeSpan.Zero, time.Offset));
            Assert.InRange(dates.Max(), before, DateTimeOffset.UtcNow.AddSeconds(2));
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
            var target = new GXDLMSProfileGeneric(profile.LogicalName);
            foreach (var capture in profile.CaptureObjects) target.CaptureObjects.Add(capture);
            var result = Exchange(client.ReadRowsByEntry(target, 1, 1));
            Assert.False(result.IsMoreData);
            var rows = Assert.IsAssignableFrom<IList>(result.Value);
            var row = Assert.IsAssignableFrom<IList>(Assert.Single(rows.Cast<object>()));
            Assert.Equal(profile.CaptureObjects.Count, row.Count);
            Assert.Equal(Convert.ToDouble(profile.Buffer[0][2], CultureInfo.InvariantCulture),
                Convert.ToDouble(row[2], CultureInfo.InvariantCulture));
            server.Reset();
        }
        finally { CultureInfo.CurrentCulture = previous; File.Delete(path); }
    }
}
