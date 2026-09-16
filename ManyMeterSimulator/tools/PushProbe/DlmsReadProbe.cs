using System.Collections;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;

sealed record ProbeRead(string Label, string LogicalName, int Attribute = 2, uint? Start = null, uint? Count = null);

static class DlmsReadProbe
{
    public static object Run(DLMSServerSession source, ProbeRead read)
    {
        var server = source.CreateReadAssociation();
        var client = new GXDLMSClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        int exchanges = 0, bytes = 0;
        string? encodingError = null;
        void CaptureEncodingError(object? sender, System.Runtime.ExceptionServices.FirstChanceExceptionEventArgs e)
        {
            if (encodingError is null)
                encodingError = $"{e.Exception.GetType().Name}: {e.Exception.Message}\n{e.Exception.StackTrace}";
        }
        AppDomain.CurrentDomain.FirstChanceException += CaptureEncodingError;
        var started = DateTimeOffset.UtcNow;
        GXReplyData Exchange(byte[][] requests)
        {
            var reply = new GXReplyData();
            void Receive(byte[] request)
            {
                if (++exchanges > 128) throw new InvalidOperationException("Probe exceeded 128 exchanges.");
                var response = server.HandleRequest(request) ?? [];
                bytes = checked(bytes + response.Length);
                if (bytes > 1_048_576) throw new InvalidOperationException("Probe exceeded 1 MiB.");
                if (response.Length == 0 || !client.GetData(response, reply) || reply.Error != 0)
                    throw new InvalidOperationException($"DLMS response error {reply.Error}, bytes {response.Length}.");
            }
            foreach (var request in requests) Receive(request);
            while (reply.IsMoreData) Receive(client.ReceiverReady(reply));
            return reply;
        }
        try
        {
            client.ParseAAREResponse(Exchange(client.AARQRequest()).Data);
            var obj = server.Items.Single(o => o.LogicalName == read.LogicalName);
            GXReplyData reply;
            if (read.Start is { } start)
            {
                if (obj is not GXDLMSProfileGeneric profile || read.Count is not { } count || count is 0 or > 2)
                    throw new ArgumentException("Select a profile and one or two rows for a bounded read.");
                var target = new GXDLMSProfileGeneric(profile.LogicalName);
                foreach (var capture in profile.CaptureObjects) target.CaptureObjects.Add(capture);
                reply = Exchange(client.ReadRowsByEntry(target, start, count));
            }
            else reply = Exchange(client.Read(obj, read.Attribute));
            int? elements = reply.Value is ICollection sequence ? sequence.Count : null;
            bool empty = reply.Value is null || read.Start is not null && elements == 0;
            return new { read.Label, read.LogicalName, status = empty ? "local-DLMS-exchange-empty" : "local-DLMS-exchange-success", exchanges, bytes, elements,
                startedUtc = started, valueType = reply.Value?.GetType().Name, value = reply.Value is byte[] raw ? Convert.ToHexString(raw) : reply.Value is GXBitString bits ? bits.ToString() : null };
        }
        catch (Exception ex) { return new { read.Label, read.LogicalName, status = "local-DLMS-exchange-failed", exchanges, error = ex.Message, encodingError }; }
        finally { AppDomain.CurrentDomain.FirstChanceException -= CaptureEncodingError; server.Reset(); }
    }
}
