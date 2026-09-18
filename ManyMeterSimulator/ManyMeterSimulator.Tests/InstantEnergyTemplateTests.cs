using System.Xml.Linq;
using Gurux.DLMS;
using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Tests;

public class InstantEnergyTemplateTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InstantPushAndPullShareTheCorrectedEnergySeeds(bool ciphering)
    {
        string path = Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml");
        var objects = new GXDLMSObjectCollection();
        new MeterObjectLoader(path).Load(objects, false);
        var profile = objects.OfType<GXDLMSProfileGeneric>().Single(p => p.LogicalName == "1.0.94.91.0.255");
        var session = new DLMSServerSession(new DLMSMeter(60001, "1.0.0.0.0.255", 16, 1), path);
        session.Initialize(true);
        var packet = DailyPushTests.Decode(Assert.Single(session.BuildPushPayloads(ciphering, DLMSServerSession.InstantDispatchLN)));
        var push = XDocument.Load(path).Descendants("GXDLMSPushSetup")
            .Single(p => (string?)p.Element("LN") == DLMSServerSession.InstantDispatchLN);
        var captures = push.Element("ObjectList")!.Elements("Item").ToArray();
        foreach (var (ln, expected) in new[] { ("1.0.1.8.0.255", 4834.96), ("1.0.9.8.0.255", 5029.88) })
        {
            int position = Array.FindIndex(captures, c => (string?)c.Element("LN") == ln);
            Assert.Equal(expected, Convert.ToDouble(packet[position]), 6);
            int column = profile.CaptureObjects.FindIndex(c => c.Key.LogicalName == ln);
            Assert.All(profile.Buffer, row => Assert.Equal(expected, Convert.ToDouble(row[column]), 6));
            Assert.Equal(expected, Convert.ToDouble(objects.OfType<GXDLMSRegister>().Single(r => r.LogicalName == ln).Value), 6);
        }
    }
}
