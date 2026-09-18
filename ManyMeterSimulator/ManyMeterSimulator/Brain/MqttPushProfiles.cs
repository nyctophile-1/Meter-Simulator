using MeterSimulator.DLMS;
using ManyMeterSimulator.Networking.Nic;

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
        Daily => "Daily",
        Esw => "ESW (Event Status Word)",
        "0.0.25.9.0.255" => "Instantaneous",
        "0.5.25.9.0.255" => "Block load",
        "0.7.25.9.0.255" => "Billing",
        _ => logicalName,
    };

    public static string? ForNic(string? selection, NicType nic)
    {
        selection = Canonical(selection);
        if (nic != NicType.MqttWirepas) return selection;
        return selection switch
        {
            "0.0.25.9.0.255" => "custom:instant",
            "0.5.25.9.0.255" => "custom:block",
            Daily => CustomDaily,
            Esw => CustomEsw,
            "0.7.25.9.0.255" => "custom:bill",
            _ => selection
        };
    }

    public static string? Canonical(string? selection) => selection switch
    {
        null or "all" => null,
        "custom:instant" => "0.0.25.9.0.255",
        "custom:block" => "0.5.25.9.0.255",
        CustomDaily or "custom:93:daily" => Daily,
        CustomEsw => Esw,
        "custom:bill" => "0.7.25.9.0.255",
        _ => selection
    };

    /// <summary>Use the encoder's loaded model and fallback capabilities without generating payloads.</summary>
    public static IReadOnlyList<MqttPushProfile> ReadTemplate(string path) =>
        DLMSServerSession.GetPushSetupLogicalNames(TemplateModelCache.Shared.Get(path))
            .Select(ln => new MqttPushProfile(ln, Label(ln))).OrderBy(p => p.LogicalName).ToArray();
}
