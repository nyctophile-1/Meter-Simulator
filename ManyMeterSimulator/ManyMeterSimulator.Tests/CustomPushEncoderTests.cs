using System.Buffers.Binary;
using Gurux.DLMS;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.SmartNic;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Tests;

public class CustomPushEncoderTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);
    private const long MeterIndex = 7284;
    private static readonly string Bits = "10000001" + new string('0', 112) + "00000001";

    public static IEnumerable<object[]> Cases() =>
        from entry in new[] { (501, "1P"), (702, "3P"), (803, "CT"), (1010, "CT") }
        from profile in CustomPushEncoder.Profiles
        select new object[] { entry.Item1, entry.Item2, profile.Key };

    [Theory]
    [MemberData(nameof(Cases))]
    public void ResolvesEveryProfileFromSelectedTemplateAndCategory(int id, string category, string key)
    {
        var (model, options) = Fixture(id, category);
        var encoder = new CustomPushEncoder(model, Options.Create(options));
        var profile = Assert.Single(encoder.GetProfiles(id), p => p.Key == key);
        byte[] packet = encoder.Encode(id, key, MeterIndex, 0xAABBCCDD, Now, Value, Bits);
        Assert.Equal((uint)(id + 123456), BinaryPrimitives.ReadUInt32LittleEndian(packet));
        Assert.Equal(packet.Length, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(4)));
        Assert.Equal(new byte[] { 1, 1 }, packet[6..8]);
        Assert.Equal(0xAABBCCDDu, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(8)));
        Assert.Equal(profile.Discriminator, packet[12]);
        Assert.Equal(1, packet[13]);
        Assert.Equal((uint)MeterIndex, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(16)));
        if (profile.Kind is "ESW" or "RTC")
        {
            Assert.Equal(Now, DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(23))).AddMinutes(-330));
            Assert.Equal(4, packet[27]);
            if (profile.Kind == "ESW")
            {
                Assert.Equal(45, packet.Length);
                Assert.Equal(128, packet[28]);
                Assert.Equal(Bits, string.Concat(packet[29..].Select(b => Convert.ToString(b, 2).PadLeft(8, '0'))));
            }
            else
            {
                Assert.Equal(33, packet.Length);
                Assert.Equal(6, packet[28]);
                Assert.Equal(packet[23..27], packet[29..33]);
            }
        }
        else
        {
            int offset = 23;
            foreach (var field in encoder.GetFields(id, key))
            {
                switch (field.ParameterName)
                {
                    case "RtcDateTime":
                        Assert.Equal(Now, DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(offset))).AddMinutes(-330));
                        offset += 4; break;
                    case "EventId":
                        Assert.Equal(profile.EventId, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(offset)));
                        offset += 2; break;
                    case "CumulativeEnergyKwhImport":
                        Assert.Equal(43_125u, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(offset)));
                        offset += 4; break;
                    case "Voltage":
                        Assert.Equal(231.5f, BitConverter.ToSingle(packet, offset));
                        offset += 4; break;
                    default: throw new InvalidOperationException("Unexpected fixture field.");
                }
            }
            Assert.Equal(packet.Length, offset);
        }
    }

    [Fact]
    public void UsesRegisteredMagicSelectionAndRejectsMissingOrAmbiguousMetadata()
    {
        var (model, options) = Fixture(702, "3P");
        model.AddMagic(999, 702);
        var encoder = new CustomPushEncoder(model, Options.Create(options));
        Assert.Throws<NotSupportedException>(() => encoder.GetProfiles(93));
        Assert.Throws<InvalidOperationException>(() => encoder.GetProfiles(702));
        options.ResponseMagicNumbers[702] = 998;
        Assert.Throws<InvalidOperationException>(() => encoder.GetProfiles(702));
        options.ResponseMagicNumbers[702] = 999;
        Assert.Equal(999u, BinaryPrimitives.ReadUInt32LittleEndian(encoder.Encode(702, "custom:rtc", MeterIndex, 1, Now, Value)));
        options.MeterCategories.Clear();
        Assert.Throws<InvalidOperationException>(() => encoder.GetProfiles(702));
    }

    [Fact]
    public void DoesNotBorrowAnotherCategoryOrProfileLayout()
    {
        var (model, options) = Fixture(501, "1P");
        options.MeterCategories[501] = "CT";
        var encoder = new CustomPushEncoder(model, Options.Create(options));
        Assert.DoesNotContain(encoder.GetProfiles(501), p => p.Key == "custom:daily");
        Assert.Throws<NotSupportedException>(() => encoder.Encode(501, "custom:daily", MeterIndex, 1, Now, Value));
        Assert.Throws<NotSupportedException>(() => encoder.Encode(501, "custom:unknown", MeterIndex, 1, Now, Value));
    }

    [Fact]
    public void RejectsMissingValuesInvalidBitsAndUnverifiedDataTypes()
    {
        var (model, options) = Fixture(501, "1P");
        var encoder = new CustomPushEncoder(model, Options.Create(options));
        Assert.Throws<InvalidOperationException>(() => encoder.Encode(501, "custom:daily", MeterIndex, 1, Now, _ => null));
        Assert.Throws<ArgumentException>(() => encoder.Encode(501, "custom:esw", MeterIndex, 1, Now, Value, "101"));
        model.AddField(10501, "DAILY_CUSTOM_PUSH_1P", new(3, "Unverified", "Ascii", 0, 0, "1P", 0));
        model.Freeze();
        Assert.Throws<NotSupportedException>(() => encoder.Encode(501, "custom:daily", MeterIndex, 1, Now,
            f => f.ParameterName == "Unverified" ? 1 : Value(f)));
    }

    [Fact]
    public void EventIdsMustBeConfiguredAndControlTheEncodedIdAndLayout()
    {
        var (model, options) = Fixture(501, "1P");
        var encoder = new CustomPushEncoder(model, Options.Create(options));
        options.EventIds[501].Remove("custom:event:voltage");
        Assert.DoesNotContain(encoder.GetProfiles(501), p => p.Key == "custom:event:voltage");
        Assert.Throws<NotSupportedException>(() => encoder.Encode(501, "custom:event:voltage", MeterIndex, 1, Now, Value));
        options.EventIds[501]["custom:event:voltage"] = 7;
        options.EventsWithPowerProfile = [7];
        byte[] packet = encoder.Encode(501, "custom:event:voltage", MeterIndex, 1, Now, Value);
        Assert.Equal(7, BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(27)));
        Assert.Equal(33, packet.Length);
        options.EventIds[501]["custom:event:voltage"] = 65536;
        Assert.Throws<InvalidOperationException>(() => encoder.GetProfiles(501));
    }

    [Fact]
    public void EventLayoutsFollowConfiguredPowerProfileMembership()
    {
        var (model, options) = Fixture(501, "1P");
        var encoder = new CustomPushEncoder(model, Options.Create(options));
        Assert.Equal(3, encoder.GetFields(501, "custom:event:voltage").Count);
        Assert.Equal(2, encoder.GetFields(501, "custom:event:power").Count);
        options.EventsWithPowerProfile = null;
        Assert.DoesNotContain(encoder.GetProfiles(501), p => p.Kind == "EVENT");
        Assert.Throws<NotSupportedException>(() => encoder.Encode(501, "custom:event:power", MeterIndex, 1, Now, Value));
    }

    private static object Value(TemplateField field) => field.ParameterName switch
    {
        "RtcDateTime" => new GXDateTime(Now.UtcDateTime),
        "CumulativeEnergyKwhImport" => 43.125m,
        "Voltage" => 231.5m,
        _ => throw new InvalidOperationException("Encoder must supply the event ID from its selected profile.")
    };

    internal static (HesDataModel Model, CustomPushOptions Options) Fixture(int id, string category)
    {
        var model = new HesDataModel();
        int profileId = 10000 + id;
        model.AddTemplate(new(id, "arbitrary-layout", 12, 0, 2, 0, false,
            profileId, profileId, profileId, profileId, profileId, null)
        { MeterProfileHeaderTemplateId = 3, EventNonProfileTemplateId = profileId + 1 });
        model.AddMagic((uint)(id + 123456), id);
        foreach (string kind in new[] { "INSTANT", "BLOCK", "DAILY", "BILL" })
        {
            var columns = category switch
            {
                "3P" => new[] { "CumulativeEnergyKwhImport", "RtcDateTime", "Voltage" },
                "CT" => new[] { "RtcDateTime", "Voltage", "CumulativeEnergyKwhImport" },
                _ => new[] { "RtcDateTime", "CumulativeEnergyKwhImport" }
            };
            for (int i = columns.Length - 1; i >= 0; i--)
                model.AddField(profileId, $"{kind}_CUSTOM_PUSH_{category}", Field(columns[i], i + 1, category));
        }
        foreach (var (kind, layout, columns) in new[]
        {
            ("EVENT", profileId, new[] { "RtcDateTime", "EventId", "Voltage" }),
            ("EVENTNONPROFILE", profileId + 1, new[] { "RtcDateTime", "EventId" })
        })
            for (int i = 0; i < columns.Length; i++) model.AddField(layout, $"{kind}_CUSTOM_PUSH_{category}", Field(columns[i], i + 1, category));
        model.Freeze();
        var eventIds = new Dictionary<string, int>
        {
            ["custom:event:voltage"] = 1, ["custom:event:current"] = 51, ["custom:event:power"] = 101,
            ["custom:event:transaction"] = 151, ["custom:event:other"] = 201,
            ["custom:event:nonrollover"] = 251, ["custom:event:control"] = 301
        };
        return (model, new() { MeterCategories = new() { [id] = category }, EventsWithPowerProfile = [1, 51, 201],
            EventIds = new() { [id] = eventIds } });
    }

    private static TemplateField Field(string name, int serial, string category) =>
        new(serial, name, name switch { "RtcDateTime" => "DateTime", "EventId" => "UInt16", "Voltage" => "Float32", _ => "UInt32" },
            name == "CumulativeEnergyKwhImport" ? -3 : 0, 0, category, 0);
}
