using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.SmartNic;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

internal static class CustomPushFixtureModel
{
    internal static CustomPushEncoder DailyEncoder(int templateId = 93)
        => Encoder(templateId, false);

    internal static CustomPushEncoder BlockEncoder(int templateId = 93)
        => Encoder(templateId, true);

    private static CustomPushEncoder Encoder(int templateId, bool block)
    {
        var model = new HesDataModel();
        model.AddTemplate(new(templateId, "captured-one-phase-layout", 12, 12, 2, 2, false, block ? 9 : null, block ? null : 9, null, null, null, null)
            { MeterProfileHeaderTemplateId = 3 });
        model.AddMagic(0x0011090E, templateId);
        string[] names = ["RtcDateTime", "CumulativeEnergyKwhImport", "CumulativeEnergyKvahImport", "CumulativeEnergyKwhExport", "CumulativeEnergyKvahExport"];
        for (int i = 0; i < names.Length; i++)
            model.AddField(9, block ? "BLOCK_CUSTOM_PUSH_1P" : "DAILY_CUSTOM_PUSH_1P", new(i + 1, names[i], i == 0 ? "DateTime" : "UInt32", i == 0 ? 0 : -3, 0, "1P", block ? 4 : 5));
        model.Freeze();
        return new(model, Options.Create(new CustomPushOptions { MeterCategories = new() { [templateId] = "1P" } }));
    }
}
