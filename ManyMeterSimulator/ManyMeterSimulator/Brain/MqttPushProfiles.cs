using System.Xml.Linq;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Brain;

public sealed record MqttPushProfile(string LogicalName, string Label);

public static class MqttPushProfiles
{
    public const string CustomDaily = "custom:93:daily";

    public static bool IsCustomDaily(MeterBatch batch) => batch.NicType == NicType.MqttWirepas && batch.HesTemplateId == 93;

    public static string Label(string? logicalName) => logicalName switch
    {
        null or "all" => "All supported profiles",
        CustomDaily => "Daily (template 93 custom push)",
        "0.0.25.9.0.255" => "Instantaneous",
        "0.5.25.9.0.255" => "Block load",
        _ => logicalName,
    };

    /// <summary>Discover all non-empty push setups, including uploaded templates. No payload generation.</summary>
    public static IReadOnlyList<MqttPushProfile> ReadTemplate(string path)
    {
        var document = XDocument.Load(path);
        return document.Descendants("GXDLMSPushSetup")
            .Where(p => p.Element("ObjectList")?.Elements("Item").Any() == true)
            .Select(p => (string?)p.Element("LN"))
            .Where(ln => !string.IsNullOrWhiteSpace(ln)).Distinct(StringComparer.Ordinal)
            .Select(ln => new MqttPushProfile(ln!, Label(ln))).OrderBy(p => p.LogicalName).ToArray();
    }
}
