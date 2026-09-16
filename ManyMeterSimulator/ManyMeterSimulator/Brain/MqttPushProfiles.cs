using System.Xml.Linq;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Brain;

public sealed record MqttPushProfile(string LogicalName, string Label);

public static class MqttPushProfiles
{
    public const string CustomDaily = "custom:daily";
    public const string CustomEsw = "custom:esw";
    public const string CustomRtc = "custom:rtc";
    public const string Esw = MeterSimulator.Models.EventStatusWord.PushLogicalName;
    public const string Daily = MeterSimulator.DLMS.DLMSServerSession.DailyPushLogicalName;

    public static string Label(string? logicalName) => logicalName switch
    {
        null or "all" => "All supported profiles",
        CustomDaily => "Daily (custom)",
        CustomEsw => "ESW (custom)",
        CustomRtc => "RTC (custom Wirepas)",
        Daily => "Daily (DLMS)",
        Esw => "ESW (Event Status Word)",
        "0.0.25.9.0.255" => "Instantaneous",
        "0.5.25.9.0.255" => "Block load",
        _ => logicalName,
    };

    /// <summary>Discover all non-empty push setups, including uploaded templates. No payload generation.</summary>
    public static IReadOnlyList<MqttPushProfile> ReadTemplate(string path)
    {
        var document = XDocument.Load(path);
        var profiles = document.Descendants("GXDLMSPushSetup")
            .Where(p => p.Element("ObjectList")?.Elements("Item").Any() == true)
            .Select(p => (string?)p.Element("LN"))
            .Where(ln => !string.IsNullOrWhiteSpace(ln)).ToList();
        var daily = document.Descendants("GXDLMSProfileGeneric").FirstOrDefault(p => (string?)p.Element("LN") == "1.0.99.2.0.255");
        string[] columns = ["0.0.1.0.0.255", "1.0.1.8.0.255", "1.0.9.8.0.255", "1.0.2.8.0.255", "1.0.10.8.0.255"];
        var captures = daily?.Element("CaptureObjects")?.Elements("Item").ToArray() ?? [];
        var positions = columns.Select(ln => Array.FindIndex(captures, c => (string?)c.Element("LN") == ln
            && (string?)c.Element("Attribute") == "2" && (string?)c.Element("Data") == "0")).ToArray();
        if (positions.All(p => p >= 0) && daily?.Element("Buffer")?.Elements("Row").Any(r =>
            positions.All(p => p < r.Elements("Cell").Count())
            && (string?)r.Elements("Cell").ElementAt(positions[0]).Attribute("Type") == "25") == true)
            profiles.Add(Daily);
        return profiles.Distinct(StringComparer.Ordinal)
            .Select(ln => new MqttPushProfile(ln!, Label(ln))).OrderBy(p => p.LogicalName).ToArray();
    }
}
