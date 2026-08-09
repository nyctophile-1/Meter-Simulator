using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Xunit;
using Xunit.Abstractions;

namespace ManyMeterSimulator.Tests;

// TEMPORARY reproduction — real client→server read of a ProfileGeneric buffer (attribute 2).
public class TempProfileReadRepro
{
    private readonly ITestOutputHelper _out;
    public TempProfileReadRepro(ITestOutputHelper o) => _out = o;

    [Fact]
    public void ReadProfileBuffer_OverTheWire()
    {
        var meter = new DLMSMeter(42, "1.0.0.0.0.255", 16, 1);
        var session = new DLMSServerSession(
            meter, Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        session.Initialize(true);

        // Public, unciphered association — enough to issue a Get.
        var client = new GXDLMSClient(true, 0x10, 1, Authentication.None, null, InterfaceType.WRAPPER);

        byte[][] aarq = client.AARQRequest();
        byte[] aare = session.HandleRequest(aarq[0]) ?? Array.Empty<byte>();
        _out.WriteLine($"AARE: {aare.Length} bytes");
        Assert.NotEmpty(aare);
        var aareReply = new GXReplyData();
        client.GetData(aare, aareReply, null);   // strip the WRAPPER header first
        client.ParseAAREResponse(aareReply.Data);

        // A profile that the diagnostic showed has rows.
        var profile = (GXDLMSProfileGeneric)session.Items
            .FindByLN(ObjectType.ProfileGeneric, "1.0.99.1.0.255")!;
        _out.WriteLine($"server-side: rows={profile.Buffer.Count} cols={profile.CaptureObjects.Count} entriesInUse={profile.EntriesInUse}");

        // --- attribute 7 (entries in use): the one the user says WORKS ---
        _out.WriteLine($"--- attr 7 --- {Exchange(session, client, profile, 7)}");

        // --- attribute 2 (the buffer), whole buffer ---
        string result = Exchange(session, client, profile, 2);
        _out.WriteLine($"--- attr 2 (all) --- {Summarize(result)}");

        // What do the rows actually claim as their timestamps?
        var first = (GXDateTime)profile.Buffer[0][0];
        var last = (GXDateTime)profile.Buffer[^1][0];
        _out.WriteLine($"buffer span: {first.Value:u}  ..  {last.Value:u}");
        _out.WriteLine($"now (UTC)  : {DateTime.UtcNow:u}");
        _out.WriteLine($"now (local): {DateTime.Now:u}");

        // --- selective access BY ENTRY (selector 2) — first 5 rows ---
        _out.WriteLine($"--- by entry (1..5) --- {Summarize(ExchangeSelective(session, client, profile, 2, 1, 5))}");

        // --- selective access BY RANGE (selector 1) — what a HES actually asks for ---
        foreach (int hours in new[] { 1, 24, 24 * 30 })
        {
            string r = Summarize(ExchangeRange(session, client, profile,
                DateTime.Now.AddHours(-hours), DateTime.Now.AddHours(1)));
            _out.WriteLine($"--- by range (last {hours}h, LOCAL) --- {r}");
        }
    }

    private static string Summarize(string s) => s.Length > 90 ? s[..90] + " …" : s;

    private string ExchangeSelective(DLMSServerSession session, GXDLMSClient client,
        GXDLMSProfileGeneric p, int attr, int start, int count)
    {
        try
        {
            byte[][] req = client.ReadRowsByEntry(p, (uint)start, (uint)count);
            return Drive(session, client, req);
        }
        catch (Exception ex) { return $"EXCEPTION {ex.GetType().Name}: {ex.Message}"; }
    }

    private string ExchangeRange(DLMSServerSession session, GXDLMSClient client,
        GXDLMSProfileGeneric p, DateTime from, DateTime to)
    {
        try
        {
            byte[][] req = client.ReadRowsByRange(p, from, to);
            return Drive(session, client, req);
        }
        catch (Exception ex) { return $"EXCEPTION {ex.GetType().Name}: {ex.Message}"; }
    }

    private string Drive(DLMSServerSession session, GXDLMSClient client, byte[][] req)
    {
        var reply = new GXReplyData();
        foreach (byte[] r in req)
        {
            byte[] resp = session.HandleRequest(r) ?? Array.Empty<byte>();
            if (resp.Length == 0) return "NO RESPONSE";
            client.GetData(resp, reply, null);
        }
        object? v = reply.Value;
        if (v is object[] arr) return arr.Length == 0 ? "EMPTY (0 rows)" : $"{arr.Length} rows";
        return $"value = {v ?? "(null)"}";
    }

    private string Exchange(DLMSServerSession session, GXDLMSClient client, GXDLMSObject obj, int attr)
    {
        try
        {
            byte[][] req = client.Read(obj, attr);
            var reply = new GXReplyData();
            foreach (byte[] r in req)
            {
                byte[] resp = session.HandleRequest(r) ?? Array.Empty<byte>();
                _out.WriteLine($"    request {resp.Length} bytes back");
                if (resp.Length == 0) return "NO RESPONSE";
                client.GetData(resp, reply, null);
            }

            object? v = reply.Value;
            if (v is object[] arr) return $"array of {arr.Length} rows";
            return $"value = {v ?? "(null)"}";
        }
        catch (Exception ex)
        {
            return $"EXCEPTION {ex.GetType().Name}: {ex.Message}";
        }
    }
}
