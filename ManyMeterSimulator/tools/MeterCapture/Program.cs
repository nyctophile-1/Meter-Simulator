using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Secure;
using MeterCapture;

if (args.Length != 1) throw new ArgumentException("Supply a non-secret capture configuration JSON path.");
var config = JsonSerializer.Deserialize<CaptureConfig>(File.ReadAllText(args[0]))!;
if (config.Rows is < 1 or > 100 || config.Port is < 1 or > 65535)
    throw new ArgumentException("Use 1..100 rows per profile and a valid port.");
var output = Path.GetFullPath(config.Output);
if (Directory.Exists(output)) throw new IOException("Use a new output directory to preserve previous captures.");
Directory.CreateDirectory(output);
var events = new List<object>();
var start = DateTimeOffset.UtcNow;
var deadline = start.AddMinutes(5);
int exchanges = 0, received = 0;
var wireProfiles = new Dictionary<GXDLMSProfileGeneric, object[][]>();
GXDLMSSecureClient client = MakeClient(false);
TcpClient? socket = null;

GXDLMSSecureClient MakeClient(bool secure)
{
    var value = new GXDLMSSecureClient(true, secure ? 48 : 16, 1,
        secure ? Authentication.High : Authentication.None,
        secure ? Environment.GetEnvironmentVariable("MAYA_CAPTURE_HLS_SECRET") : null, InterfaceType.WRAPPER);
    if (secure)
    {
        var key = Encoding.ASCII.GetBytes(Environment.GetEnvironmentVariable("MAYA_CAPTURE_GLOBAL_KEY")
            ?? throw new ArgumentException("Set the capture key environment variable."));
        if (key.Length != 16 || value.Password is not { Length: 16 })
            throw new ArgumentException("This capture contract requires 16-byte GlobalKey and HLS secret.");
        value.Ciphering.AuthenticationKey = key;
        value.Ciphering.BlockCipherKey = key;
        value.Ciphering.Security = Security.AuthenticationEncryption;
    }
    return value;
}

void Connect()
{
    socket = new TcpClient(AddressFamily.InterNetworkV6);
    if (config.InterfaceIndex is { } index)
        socket.Client.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)31, index);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    socket.ConnectAsync(IPAddress.Parse(config.Host), config.Port, timeout.Token).AsTask().GetAwaiter().GetResult();
    socket.ReceiveTimeout = socket.SendTimeout = 10000;
}

GXReplyData Exchange(byte[][] requests)
{
    var reply = new GXReplyData();
    int blocks = 0;
    void Send(byte[] request)
    {
        if (DateTimeOffset.UtcNow > deadline || ++exchanges > 3000 || ++blocks > 256 || received > 8_388_608)
            throw new InvalidOperationException("Capture time, exchange, block or byte limit reached.");
        var stream = socket!.GetStream();
        stream.Write(request);
        var header = new byte[8];
        stream.ReadExactly(header);
        if (header[0] != 0 || header[1] != 1) throw new InvalidDataException("Expected DLMS wrapper version 1.");
        int length = (header[6] << 8) | header[7];
        var packet = new byte[8 + length];
        header.CopyTo(packet, 0);
        stream.ReadExactly(packet.AsSpan(8));
        received += packet.Length;
        if (!client.GetData(packet, reply)) throw new InvalidDataException("Incomplete DLMS response.");
        if (reply.Error != 0) throw new GXDLMSException(reply.Error);
    }
    foreach (var request in requests) Send(request);
    while (reply.IsMoreData) Send(client.ReceiverReady(reply));
    return reply;
}

void Associate()
{
    Connect();
    client.ParseAAREResponse(Exchange(client.AARQRequest()).Data);
    if (client.Authentication > Authentication.Low)
        client.ParseApplicationAssociationResponse(Exchange(client.GetApplicationAssociationRequest()).Data);
}

void Disconnect()
{
    if (socket is null) return;
    try { var request = client.DisconnectRequest(); if (request is { Length: > 0 }) Exchange([request]); }
    catch { }
    socket.Dispose(); socket = null;
}

bool Read(GXDLMSObject obj, int attribute)
{
    try
    {
        var reply = Exchange(client.Read(obj, attribute));
        client.UpdateValue(obj, attribute, reply.Value);
        events.Add(new { ln = obj.LogicalName, objectType = obj.ObjectType.ToString(), attribute, status = "read" });
        return true;
    }
    catch (GXDLMSException ex)
    {
        events.Add(new { ln = obj.LogicalName, objectType = obj.ObjectType.ToString(), attribute, status = "denied-or-unavailable", error = ex.Message });
        return false;
    }
}

string status = "failed";
try
{
    Associate();
    if (config.Secure)
    {
        var counter = new GXDLMSData("0.0.43.1.3.255");
        if (!Read(counter, 2)) throw new InvalidOperationException("Cannot read the HES user-association invocation counter.");
        uint nextCounter = checked(Convert.ToUInt32(counter.Value) + 1);
        Disconnect();
        client = MakeClient(true);
        client.Ciphering.InvocationCounter = nextCounter;
        Associate();
    }
    client.ParseObjects(Exchange(client.GetObjectsRequest()).Data, true);
    if (client.Objects.Count > 500) throw new InvalidOperationException("Association exceeds the 500-object capture limit.");
    foreach (var ln in new[] { "0.0.94.91.9.255", "0.0.94.91.11.255", "0.0.96.1.0.255" })
    {
        var obj = client.Objects.FindByLN(ObjectType.Data, ln) ?? new GXDLMSData(ln);
        if (Read(obj, 2))
        {
            var value = ((GXDLMSData)obj).Value;
            events.Add(new { identity = ln, value = value is byte[] bytes ? Encoding.ASCII.GetString(bytes) : Convert.ToString(value) });
        }
    }
    if (!config.DiscoveryOnly)
    {
        var profiles = client.Objects.OfType<GXDLMSProfileGeneric>()
            .Where(p => config.ProfileLogicalNames is null || config.ProfileLogicalNames.Contains(p.LogicalName)).ToArray();
        if (config.ProfileLogicalNames?.Except(profiles.Select(p => p.LogicalName)).Any() == true)
            throw new InvalidDataException("A selected profile is absent from the meter association.");
        if (config.ProfileLogicalNames is not null)
            foreach (var profile in profiles) Read(profile, 3);
        if (config.ReadMissingCaptureScalers)
        {
            foreach (var obj in profiles.SelectMany(p => p.CaptureObjects).Select(c => c.Key)
                .DistinctBy(o => (o.ObjectType, o.LogicalName)))
            {
                if (client.Objects.FindByLN(obj.ObjectType, obj.LogicalName) is not null) continue;
                if (obj is not GXDLMSRegister && obj is not GXDLMSDemandRegister) continue;
                bool read = Read(obj, obj is GXDLMSDemandRegister ? 4 : 3);
                events.Add(new { ln = obj.LogicalName, status = "capture-reference-scaler-probe", read,
                    objectType = obj.ObjectType.ToString(), versionFromAssociation = false,
                    scaler = read ? obj is GXDLMSRegister register ? register.Scaler : ((GXDLMSDemandRegister)obj).Scaler : (double?)null,
                    unit = read ? obj is GXDLMSRegister unitRegister ? unitRegister.Unit.ToString() : ((GXDLMSDemandRegister)obj).Unit.ToString() : null });
            }
        }
        var required = profiles.SelectMany(p => p.CaptureObjects).Select(c => c.Key.LogicalName).ToHashSet();
        foreach (var obj in client.Objects)
        {
            if (obj is GXDLMSProfileGeneric) continue;
            if (config.ProfileLogicalNames is not null && !required.Contains(obj.LogicalName)) continue;
            foreach (int attribute in ((IGXDLMSBase)obj).GetAttributeIndexToRead(true))
            {
                if (obj is GXDLMSAssociationLogicalName or GXDLMSSecuritySetup || attribute == 1) continue;
                Read(obj, attribute);
            }
        }
        foreach (var profile in profiles)
        {
            foreach (int attribute in new[] { 3, 4, 5, 6, 7, 8 }) Read(profile, attribute);
            uint count = Math.Min(profile.EntriesInUse, (uint)config.Rows);
            if (count == 0 || profile.CaptureObjects.Count == 0) continue;
            try
            {
                var reply = Exchange(client.ReadRowsByEntry(profile, profile.EntriesInUse - count + 1, count));
                var wireRows = ProfileWireValues.Snapshot(reply.Value);
                if (reply.Value is System.Collections.IEnumerable rows)
                {
                    var rawRows = rows.Cast<object>().Select(row => ((System.Collections.IEnumerable)row).Cast<object>()
                        .Select(value => new { type = value?.GetType().Name, value = value is byte[] bytes ? Convert.ToHexString(bytes)
                            : Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) }).ToArray()).ToArray();
                    File.WriteAllText(Path.Combine(output, "raw-profile-" + profile.LogicalName + ".json"),
                        JsonSerializer.Serialize(rawRows, new JsonSerializerOptions { WriteIndented = true }));
                }
                client.UpdateValue(profile, 2, reply.Value);
                wireProfiles.Add(profile, wireRows);
                events.Add(new { ln = profile.LogicalName, attribute = 2, status = "read", rows = profile.Buffer.Count });
            }
            catch (GXDLMSException ex)
            { events.Add(new { ln = profile.LogicalName, attribute = 2, status = "denied-or-unavailable", error = ex.Message }); }
        }
    }
    client.Objects.Save(Path.Combine(output, "meter.xml"), new GXXmlWriterSettings { UseMeterTime = true, IgnoreDefaultValues = false });
    foreach (var pair in wireProfiles) ProfileWireValues.Restore(pair.Key, pair.Value);
    client.Objects.Save(Path.Combine(output, "meter-profile-wire.xml"), new GXXmlWriterSettings { UseMeterTime = true, IgnoreDefaultValues = false });
    status = "captured";
}
catch (Exception ex)
{
    events.Add(new { status = "capture-stopped", errorType = ex.GetType().Name, error = ex.Message });
}
finally
{
    Disconnect();
    string xmlPath = Path.Combine(output, "meter.xml");
    var report = new { status, startedUtc = start, completedUtc = DateTimeOffset.UtcNow, config.Host, config.Port,
        config.HesTemplateId, config.Secure, config.DiscoveryOnly, config.Rows, exchanges, received,
        objects = client.Objects.Count, xmlSha256 = File.Exists(xmlPath) ? Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(xmlPath))).ToLowerInvariant() : null,
        profileWireXmlSha256 = File.Exists(Path.Combine(output, "meter-profile-wire.xml"))
            ? Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(output, "meter-profile-wire.xml")))).ToLowerInvariant() : null,
        events };
    File.WriteAllText(Path.Combine(output, "capture.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine(JsonSerializer.Serialize(new { status, output, objects = client.Objects.Count, exchanges, received }));
}
return status == "captured" ? 0 : 1;

sealed record CaptureConfig(string Host, int Port, int HesTemplateId, string Output,
    int? InterfaceIndex = null, bool Secure = false, bool DiscoveryOnly = true, int Rows = 13,
    string[]? ProfileLogicalNames = null, bool ReadMissingCaptureScalers = false);
