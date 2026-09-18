using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Provisioning;

public sealed record HesRegistrationDefinition(
    long StartIndex, long Count, int TemplateId, string ModelHash,
    string Manufacturer, string Firmware, string MeterType, string Category, string Rating,
    int? Year, int? CtRatio, int? PtRatio, int? CapturePeriod,
    string AddressPrefix, int Port, string Module, string Gateway, string Sink, int Endpoint,
    string GlobalKey, string HlsSecret, string LlsSecret)
{
    public long EndIndex => checked(StartIndex + Count - 1);
    [JsonIgnore]
    public string Fingerprint => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(this)));
    public override string ToString() => "HES registration definition (security redacted)";
    // Stable, application-specific ownership marker; serial prefix or range alone is insufficient.
    public static Guid OwnershipId(long index) => new(SHA256.HashData(
        Encoding.UTF8.GetBytes($"MAYA/HES-registration/v1/{MeterNodeIds.Format(index)}/{MeterIdentity.Serial(index)}"))[..16]);
}

public sealed class HesRegistrationDefinitionFactory(
    TemplateRegistry templates, IOptions<BrainOptions> brain, IOptions<TcpOptions> tcp,
    IOptions<CustomPushOptions> custom, IOptions<PushOptions> push)
{
    public HesRegistrationDefinition Create(MeterBatch batch, int templateId)
    {
        if (templateId <= 0 || batch.HesTemplateId is > 0 && templateId != batch.HesTemplateId)
            throw new InvalidOperationException("Use the HES template ID assigned to this batch.");
        string path = templates.ResolveOrThrow(batch.TemplateName);
        var meter = new DLMSMeter(batch.StartIndex, brain.Value.LogicalName, brain.Value.ClientAddress, brain.Value.ServerAddress);
        var session = new DLMSServerSession(meter, path, pushConfig: null);
        session.Initialize(true);
        string Value(string obis) => meter.GetValue(obis) switch
        {
            byte[] bytes => Encoding.ASCII.GetString(bytes),
            var value => Convert.ToString(value, CultureInfo.InvariantCulture) ?? ""
        };
        int? Number(string obis) => int.TryParse(Value(obis), CultureInfo.InvariantCulture, out int n) ? n : null;
        string category = Value("0.0.94.91.11.255");
        string type = Value("0.0.94.91.9.255");
        if (string.IsNullOrWhiteSpace(category) || string.IsNullOrWhiteSpace(type))
            throw new InvalidOperationException("The batch model must define meter category and meter type before registration.");
        var route = batch.NicType switch
        {
            NicType.Tcp4G => ("direct_tcp", "direct_tcp", -1),
            NicType.Mqtt4G or NicType.Mqtt4GImg => ("direct_4g", "direct_4g", -1),
            NicType.MqttWirepas => (custom.Value.WirepasGatewayId, custom.Value.WirepasSinkId, 3),
            NicType.MqttKmesh => (push.Value.KmeshGatewayId, push.Value.KmeshSinkId.ToString(CultureInfo.InvariantCulture), -1),
            _ => throw new InvalidOperationException("Unsupported batch transport.")
        };
        if (string.IsNullOrWhiteSpace(route.Item1) || string.IsNullOrWhiteSpace(route.Item2) || route.Item1.Length > 32 || route.Item2.Length > 32)
            throw new InvalidOperationException("Configure a valid gateway and sink (at most 32 characters) before provisioning.");
        string rating = Value("0.0.94.91.12.255");
        if (rating.Length > 10) throw new InvalidOperationException("Model current rating exceeds the HES nameplate limit.");
        return new(batch.StartIndex, batch.Count, templateId,
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))),
            Value("0.0.96.1.1.255"), Value("1.0.0.2.0.255"), type, category, rating,
            Number("0.0.96.1.4.255"), Number("1.0.0.4.2.255"), Number("1.0.0.4.3.255"), Number("1.0.0.8.4.255"),
            tcp.Value.AddressPrefix, tcp.Value.ListenPort,
            batch.NicType is NicType.MqttWirepas or NicType.MqttKmesh ? "RF" : "4G",
            route.Item1, route.Item2, route.Item3,
            Encoding.ASCII.GetString(meter.BlockCipherKey!), Encoding.ASCII.GetString(meter.HLSKey!), Encoding.ASCII.GetString(meter.LLSKey!));
    }
}
