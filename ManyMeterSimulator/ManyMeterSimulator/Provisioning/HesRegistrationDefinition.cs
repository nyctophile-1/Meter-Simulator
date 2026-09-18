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
    string GlobalKey, string HlsSecret, string LlsSecret, int BatchId = 0, bool GroupGateways = false)
{
    public long EndIndex => checked(StartIndex + Count - 1);
    [JsonIgnore]
    public string Fingerprint => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(this)));
    public override string ToString() => "HES registration definition (security redacted)";
    public (string Gateway, string Sink) RouteFor(long index)
    {
        if (index < StartIndex || index > EndIndex) throw new ArgumentOutOfRangeException(nameof(index));
        if (!GroupGateways) return (Gateway, Sink);
        if (Module == "KMesh")
        {
            var route = BatchGatewayAssignment.ForKmesh(BatchId, StartIndex, index);
            return (route.Gateway, route.Sink.ToString(CultureInfo.InvariantCulture));
        }
        return BatchGatewayAssignment.For(BatchId, StartIndex, index);
    }
    public static string DeviceId(long index) => MeterNodeIds.Format(index) + "MAYA";
    // Stable, application-specific ownership marker; serial prefix or range alone is insufficient.
    public static Guid OwnershipId(long index) => new(SHA256.HashData(
        Encoding.UTF8.GetBytes($"MAYA/HES-registration/v1/{MeterNodeIds.Format(index)}/{MeterIdentity.Serial(index)}"))[..16]);
}

public sealed record HesRegistrationEdits
{
    public string Category { get; set; } = "D1";
    public string MeterType { get; set; } = "6";
    public string Manufacturer { get; set; } = "Kimbal";
    public string Firmware { get; set; } = "MY01.1";
    public string Rating { get; set; } = "";
    public int? Year { get; set; }
    public int CtRatio { get; set; } = 1;
    public int PtRatio { get; set; } = 1;
    public int CapturePeriodMinutes { get; set; } = 15;

    public static HesRegistrationEdits From(HesRegistrationDefinition d) => new()
    {
        Category = d.Category, MeterType = d.MeterType, Manufacturer = d.Manufacturer, Firmware = d.Firmware,
        Rating = d.Rating, Year = d.Year, CtRatio = d.CtRatio ?? 1, PtRatio = d.PtRatio ?? 1, CapturePeriodMinutes = d.CapturePeriod ?? 15
    };

    public HesRegistrationDefinition Apply(HesRegistrationDefinition d)
    {
        if (Category is not ("D1" or "D2" or "D3")) throw new InvalidOperationException("Select meter category D1, D2 or D3.");
        if (CtRatio < 1 || PtRatio < 1) throw new InvalidOperationException("CT and PT ratios must be positive integers.");
        if (CapturePeriodMinutes is not (15 or 30 or 60)) throw new InvalidOperationException("Block capture period must be 15, 30 or 60 minutes.");
        if (Year is < 1900 or > 9999) throw new InvalidOperationException("Enter a valid manufacture year.");
        static string Field(string? value, string name, int max, bool required = true)
        {
            string text = value?.Trim() ?? "";
            if (required && text.Length == 0 || text.Length > max || text.Any(char.IsControl))
                throw new InvalidOperationException($"{name} must {(required ? "contain 1–" : "contain at most ")}{max} printable characters.");
            return text;
        }
        return d with
        {
            Category = Category, MeterType = Field(MeterType, "Meter type", 20), Manufacturer = Field(Manufacturer, "Manufacturer", 100),
            Firmware = Field(Firmware, "Firmware", 100), Rating = Field(Rating, "Rating", 10, false), Year = Year,
            CtRatio = CtRatio, PtRatio = PtRatio, CapturePeriod = CapturePeriodMinutes
        };
    }
}

public sealed class HesRegistrationDefinitionFactory(
    TemplateRegistry templates, IOptions<BrainOptions> brain, IOptions<TcpOptions> tcp)
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
            NicType.MqttWirepas => ($"gate_{batch.Id}_1", "sink0", 3),
            NicType.MqttKmesh => ($"gate_{batch.Id}_1", "0", -1),
            _ => throw new InvalidOperationException("Unsupported batch transport.")
        };
        if (string.IsNullOrWhiteSpace(route.Item1) || string.IsNullOrWhiteSpace(route.Item2) || route.Item1.Length > 32 || route.Item2.Length > 32)
            throw new InvalidOperationException("Configure a valid gateway and sink (at most 32 characters) before provisioning.");
        string rating = Value("0.0.94.91.12.255");
        if (rating.Length > 10) throw new InvalidOperationException("Model current rating exceeds the HES nameplate limit.");
        return new(batch.StartIndex, batch.Count, templateId,
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))),
            "Kimbal", "MY01.1", type, category, rating,
            Number("0.0.96.1.4.255"), PositiveOrOne(Number("1.0.0.4.2.255")), PositiveOrOne(Number("1.0.0.4.3.255")), CaptureMinutes(Number("1.0.0.8.4.255")),
            tcp.Value.AddressPrefix, tcp.Value.ListenPort,
            batch.NicType switch { NicType.Tcp4G => "TCP", NicType.MqttWirepas => "RF", NicType.MqttKmesh => "KMesh", _ => "MQTT4G" },
            route.Item1, route.Item2, route.Item3,
            Encoding.ASCII.GetString(meter.BlockCipherKey!), Encoding.ASCII.GetString(meter.HLSKey!), Encoding.ASCII.GetString(meter.LLSKey!), batch.Id, batch.NicType is NicType.MqttWirepas or NicType.MqttKmesh);
    }

    private static int PositiveOrOne(int? value) => value is > 0 ? value.Value : 1;
    private static int CaptureMinutes(int? seconds) => seconds is 900 or 1800 or 3600 ? seconds.Value / 60 : 15;
}
