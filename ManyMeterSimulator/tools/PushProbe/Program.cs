using ManyMeterSimulator.Provisioning;
using System.Security.Cryptography;
using System.Text.Json;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.SmartNic;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MeterSimulator.DLMS;
using MeterSimulator.Models;

// Generates bounded diagnostic artifacts. It never connects to a broker.
if (args.Length != 1) throw new ArgumentException("Supply one probe configuration JSON path.");
var configPath = Path.GetFullPath(args[0]);
var config = JsonSerializer.Deserialize<ProbeConfig>(File.ReadAllText(configPath))
    ?? throw new ArgumentException("Missing probe configuration.");
if (config.Index <= 0 || config.Profiles.Length == 0 && config.Reads.Length == 0 && !config.Routing) throw new ArgumentException("Select a meter index and profiles, reads or routing.");
var nic = Enum.Parse<NicType>(config.Nic);
var meter = new MeterRef(config.Index, nic);
var session = new DLMSServerSession(new DLMSMeter(config.Index, "1.0.0.0.0.255", 16, 1), Path.GetFullPath(config.Template));
session.Initialize(true);
var output = Path.GetFullPath(config.Output);
Directory.CreateDirectory(output);
var results = new List<object>();
foreach (var profile in config.Profiles)
{
    try
    {
        IReadOnlyList<NicPublish> messages;
        if (profile.StartsWith("custom:", StringComparison.Ordinal))
        {
            if (config.HesTemplateId is not int templateId || nic != NicType.MqttWirepas || config.DataModelDirectory is null)
                throw new NotSupportedException("Custom push requires a Wirepas template mapping and HES data model directory.");
            var model = new HesDataModelLoader(NullLogger<HesDataModelLoader>.Instance).Load(config.DataModelDirectory);
            var customOptions = new CustomPushOptions { MeterCategories = new() { [templateId] = config.MeterCategory ?? "" },
                EventsWithPowerProfile = config.EventsWithPowerProfile, ResponseTimestampOffsetMinutes = config.ResponseTimestampOffsetMinutes,
                EventIds = new() { [templateId] = config.EventIds } };
            if (config.MagicNumber is uint magic) customOptions.ResponseMagicNumbers[templateId] = magic;
            var encoder = new CustomPushEncoder(model, Options.Create(customOptions));
            string key = profile == "custom:93:daily" ? MqttPushProfiles.CustomDaily : profile;
            var definition = encoder.GetProfiles(templateId).Single(p => p.Key == key);
            var timestamp = DateTimeOffset.UtcNow;
            var framed = encoder.Encode(templateId, key, meter.Index, unchecked((uint)Random.Shared.NextInt64()), timestamp,
                field => CustomProfileDataGenerator.Value(field, meter.Index, timestamp, definition.Kind, definition.EventId),
                definition.Kind == "ESW" ? session.GetEventStatusWord() : null);
            messages = [WirepasCustomPushEnvelope.Create(config.Gateway, config.Sink, meter.NodeId, 10, framed)];
        }
        else
        {
            if (!session.GetPushSetupLogicalNames().Contains(profile))
                throw new NotSupportedException("Template/session does not advertise this push setup.");
            var codec = new NicCodecFactory().CreatePush(nic, config.Gateway, config.Sink, config.Gateway, 1)
                ?? throw new NotSupportedException("No MQTT codec for this NIC.");
            messages = session.BuildPushPayloads(config.Ciphering, profile).SelectMany(p => codec.EncodePush(meter.NodeId, p)).ToArray();
        }
        foreach (var message in messages)
        {
            var bytes = message.Payload.ToArray();
            var digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var file = Path.Combine(output, digest + ".bin");
            File.WriteAllBytes(file, bytes);
            results.Add(new { profile, status = "generated", meter.NodeId, meter.Serial, message.Topic, bytes = bytes.Length, sha256 = digest, file });
        }
    }
    catch (Exception ex) { results.Add(new { profile, status = "unsupported-or-error", error = ex.Message }); }
}
if (config.Routing)
{
    var routingBatch = new MeterBatch
    {
        Id = config.BatchId,
        Name = "probe",
        TemplateName = config.Template,
        StartIndex = config.BatchStartIndex,
        Count = checked(config.Index - config.BatchStartIndex + 1),
        NicType = nic
    };

    byte[] bytes = [];
    string digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    string file = Path.Combine(output, digest + ".bin");
    File.WriteAllBytes(file, bytes);
    results.Add(new { profile = "fakerouting", status = "generated", meter.NodeId, meter.Serial,
        Topic = NicTopics.FakeRouting(routingBatch, meter.Index), bytes = bytes.Length, sha256 = digest, file });
}
var report = new { generatedUtc = DateTimeOffset.UtcNow, configPath, config.Index, config.HesTemplateId,
    templateSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(config.Template))).ToLowerInvariant(),
    advertisedProfiles = session.GetPushSetupLogicalNames(), results };
File.WriteAllText(Path.Combine(output, "generated.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine(JsonSerializer.Serialize(report));
if (config.Reads.Length > 0)
    File.WriteAllText(Path.Combine(output, "local-pull.json"), JsonSerializer.Serialize(
        config.Reads.Select(read => DlmsReadProbe.Run(session, read)), new JsonSerializerOptions { WriteIndented = true }));

sealed record ProbeConfig(string Template, long Index, string Nic, int? HesTemplateId, uint? MagicNumber,
    string Gateway, string Sink, bool Ciphering, string Output, string[] Profiles)
{
    public ProbeRead[] Reads { get; init; } = [];
    public bool Routing { get; init; }
    public int BatchId { get; init; } = 1;
    public long BatchStartIndex { get; init; } = 1;
    public string? DataModelDirectory { get; init; }
    public string? MeterCategory { get; init; }
    public int[]? EventsWithPowerProfile { get; init; }
    public int ResponseTimestampOffsetMinutes { get; init; } = 330;
    public Dictionary<string, int> EventIds { get; init; } = new();
}
