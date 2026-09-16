using System.Collections;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterCapture;
using MeterSimulator.DLMS;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Tests;

public class ProfileWireCaptureTests
{
    [Fact]
    public void PhysicalDailyWireValuesSurviveClientExportSimulatorPullAndPush()
    {
        var objects = GXDLMSObjectCollection.Load(Path.Combine(AppContext.BaseDirectory, "Templates", "D1_Master.xml"));
        var profile = (GXDLMSProfileGeneric)objects.FindByLN(ObjectType.ProfileGeneric, "1.0.99.2.0.255");
        for (int i = 0; i < profile.CaptureObjects.Count; i++)
        {
            var capture = profile.CaptureObjects[i];
            profile.CaptureObjects[i] = new(objects.FindByLN(capture.Key.ObjectType, capture.Key.LogicalName), capture.Value);
        }
        Assert.Equal(1000, ((GXDLMSRegister)profile.CaptureObjects[1].Key).Scaler);
        object[] raw = [new object[] { Convert.FromHexString("07EA090EFF000000FF014A00"), 847.8488f, 880.43933f, 0f, 0f }];
        var snapshot = ProfileWireValues.Snapshot(raw);
        var client = new GXDLMSClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        profile.Buffer.Clear();
        client.UpdateValue(profile, 2, raw);
        Assert.Equal((double)847.8488f * 1000, Convert.ToDouble(profile.Buffer[0][1]));
        ProfileWireValues.Restore(profile, snapshot);
        Assert.Equal(847.8488f, Assert.IsType<float>(profile.Buffer[0][1]));
        string path = Path.Combine(Path.GetTempPath(), "profile-wire-" + Guid.NewGuid().ToString("N") + ".xml");
        DLMSServerSession? server = null;
        try
        {
            objects.Save(path, new GXXmlWriterSettings { UseMeterTime = true, IgnoreDefaultValues = false });
            server = new DLMSServerSession(new DLMSMeter(923, "1.0.0.0.0.255", 16, 1), path);
            server.Initialize(true);
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
            var reply = Exchange(client.ReadRowsByEntry(profile, 1, 1));
            Assert.False(reply.IsMoreData);
            var row = Assert.IsAssignableFrom<IList>(Assert.Single(Assert.IsAssignableFrom<IList>(reply.Value).Cast<object>()));
            var push = DailyPushTests.Decode(Assert.Single(server.BuildPushPayloads(false, DLMSServerSession.DailyPushLogicalName)));
            for (int i = 1; i < 5; i++)
            {
                Assert.Equal(Convert.ToDouble(snapshot[0][i]), Convert.ToDouble(row[i]));
                Assert.Equal(snapshot[0][i], Assert.IsType<float>(push[i + 2]));
            }
        }
        finally { server?.Reset(); File.Delete(path); }
    }
}
