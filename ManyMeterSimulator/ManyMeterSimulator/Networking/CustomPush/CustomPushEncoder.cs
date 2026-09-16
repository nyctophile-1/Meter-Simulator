using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using Gurux.DLMS.Objects;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.SmartNic;
using MeterSimulator.Models;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Networking.CustomPush;

public sealed record CustomPushProfile(string Key, string Label, byte Discriminator, string Kind, int EventId = 0);

public sealed class CustomPushEncoder(HesDataModel model, IOptions<CustomPushOptions> options)
{
    public static readonly IReadOnlyList<CustomPushProfile> Profiles = Array.AsReadOnly(new[]
    {
        new CustomPushProfile("custom:instant", "Instant (custom)", 1, "INSTANT"),
        new CustomPushProfile("custom:block", "Block (custom)", 6, "BLOCK"),
        new CustomPushProfile("custom:daily", "Daily (custom)", 7, "DAILY"),
        new CustomPushProfile("custom:bill", "Billing (custom)", 8, "BILL"),
        new CustomPushProfile("custom:event:voltage", "Voltage events (custom)", 9, "EVENT"),
        new CustomPushProfile("custom:event:current", "Current events (custom)", 10, "EVENT"),
        new CustomPushProfile("custom:event:power", "Power events (custom)", 11, "EVENT"),
        new CustomPushProfile("custom:event:transaction", "Transaction events (custom)", 12, "EVENT"),
        new CustomPushProfile("custom:event:other", "Other events (custom)", 13, "EVENT"),
        new CustomPushProfile("custom:event:nonrollover", "Non-rollover events (custom)", 14, "EVENT"),
        new CustomPushProfile("custom:event:control", "Control events (custom)", 15, "EVENT"),
        new CustomPushProfile("custom:esw", "ESW (custom)", 5, "ESW"),
        new CustomPushProfile("custom:rtc", "RTC (custom Wirepas)", 48, "RTC")
    });

    private readonly CustomPushOptions _options = options.Value;

    public bool IsCustomTemplate(int? templateId) => templateId is int id &&
        model.TryGetTemplate(id, out var template) && template.PushPayloadType == 2;

    public bool HasTemplate(int templateId) => model.TryGetTemplate(templateId, out _);

    public IReadOnlyList<CustomPushProfile> GetProfiles(int templateId)
    {
        var (template, category, _) = Resolve(templateId);
        return Profiles.Where(p => p.Kind != "EVENT" || _options.EventIds.TryGetValue(templateId, out var ids) && ids.ContainsKey(p.Key))
            .Select(p => ResolveProfile(templateId, p.Key))
            .Where(p => p.Kind is "ESW" or "RTC" || Fields(template, category, p).Count > 0).ToArray();
    }

    public IReadOnlyList<TemplateField> GetFields(int templateId, string profileKey)
    {
        var (template, category, _) = Resolve(templateId);
        return Fields(template, category, ResolveProfile(templateId, profileKey));
    }

    public byte[] Encode(int templateId, string profileKey, long meterIndex, uint frameId,
        DateTimeOffset timestamp, Func<TemplateField, object?> valueForField, string? eventStatusWord = null)
    {
        var (template, category, magic) = Resolve(templateId);
        var profile = ResolveProfile(templateId, profileKey);
        var fields = Fields(template, category, profile);
        if (profile.Kind is not ("ESW" or "RTC") && fields.Count == 0)
            throw new NotSupportedException($"No {profile.Kind} custom-push layout for template {templateId}/{category}.");
        using var body = new MemoryStream();
        body.Write(Header(profile.Discriminator, meterIndex));
        if (profile.Kind is "ESW" or "RTC")
        {
            uint seconds = checked((uint)timestamp.AddMinutes(_options.ResponseTimestampOffsetMinutes).ToUnixTimeSeconds());
            using var writer = new BinaryWriter(body, Encoding.UTF8, leaveOpen: true);
            writer.Write(seconds);
            if (profile.Kind == "ESW")
            {
                EventStatusWord.Validate(eventStatusWord);
                writer.Write((byte)4);
                writer.Write((byte)128);
                for (int first = 0; first < 128; first += 8)
                    writer.Write(Convert.ToByte(eventStatusWord!.Substring(first, 8), 2));
            }
            else
            {
                writer.Write((byte)4);
                writer.Write((byte)6);
                writer.Write(seconds);
            }
        }
        else
        {
            foreach (var field in fields)
            {
                object? value = field.ParameterName == "EventId" ? profile.EventId : valueForField(field);
                if (value is null) throw new InvalidOperationException($"No value supplied for {profile.Kind}/{field.ParameterName}.");
                body.Write(CustomProfileCommand.EncodeField(field, value, new GXDLMSData(), _options.ResponseTimestampOffsetMinutes));
            }
        }
        return CustomPushFramer.FrameNew(body.ToArray(), frameId, magic);
    }

    private (MeterTemplateRow Template, string Category, uint Magic) Resolve(int templateId)
    {
        if (!model.TryGetTemplate(templateId, out var template))
            throw new NotSupportedException($"HES template {templateId} is missing from the configured data model.");
        if (template.PushPayloadType != 2)
            throw new NotSupportedException($"HES template {templateId} does not declare custom push payloads.");
        if (template.PushHeaderLength != 12 || template.MeterProfileHeaderTemplateId != 3)
            throw new NotSupportedException("This encoder requires the verified 12-byte transport and 11-byte profile header layouts.");
        if (!_options.MeterCategories.TryGetValue(templateId, out string? category) || category is not ("1P" or "3P" or "CT"))
            throw new InvalidOperationException($"Configure CustomPush:MeterCategories:{templateId} as 1P, 3P or CT from HES metadata.");
        var magics = model.GetMagicNumbersForTemplate(templateId);
        if (_options.ResponseMagicNumbers.TryGetValue(templateId, out uint chosen))
        {
            if (!magics.Contains(chosen)) throw new InvalidOperationException($"Configured magic is not registered for template {templateId}.");
            return (template, category, chosen);
        }
        if (magics.Count != 1)
            throw new InvalidOperationException($"Template {templateId} has {magics.Count} magic mappings; configure one registered response magic.");
        return (template, category, magics[0]);
    }

    private IReadOnlyList<TemplateField> Fields(MeterTemplateRow template, string category, CustomPushProfile profile)
    {
        if (profile.Kind is "ESW" or "RTC") return [];
        string kind = profile.Kind;
        if (kind == "EVENT")
        {
            if (_options.EventsWithPowerProfile is null) return [];
            if (!_options.EventsWithPowerProfile.Contains(profile.EventId)) kind = "EVENTNONPROFILE";
        }
        int? id = kind switch
        {
            "INSTANT" => template.InstantTemplateId,
            "BLOCK" => template.BlockTemplateId,
            "DAILY" => template.DailyTemplateId,
            "BILL" => template.BillTemplateId,
            "EVENT" => template.EventTemplateId,
            "EVENTNONPROFILE" => template.EventNonProfileTemplateId,
            _ => null
        };
        if (id is null) return [];
        var fields = model.GetFields(id.Value, $"{kind}_CUSTOM_PUSH_{category}");
        if (fields.Select(f => f.SerialNumber).Distinct().Count() != fields.Count)
            throw new InvalidOperationException($"Duplicate field positions in {kind} push layout {id}/{category}.");
        return fields;
    }

    private static CustomPushProfile Find(string key) => Profiles.SingleOrDefault(p => p.Key == key)
        ?? throw new NotSupportedException($"Unknown custom push profile {key}.");

    private CustomPushProfile ResolveProfile(int templateId, string key)
    {
        var profile = Find(key);
        if (profile.Kind != "EVENT") return profile;
        if (!_options.EventIds.TryGetValue(templateId, out var ids) || !ids.TryGetValue(key, out int eventId))
            throw new NotSupportedException($"Configure a HES-supported event ID for template {templateId}/{key}.");
        if (eventId is <= 0 or > ushort.MaxValue)
            throw new InvalidOperationException("Custom event ID must fit the protocol's positive UInt16 range.");
        return profile with { EventId = eventId };
    }

    private static byte[] Header(byte discriminator, long meterIndex)
    {
        if (meterIndex <= 0) throw new ArgumentOutOfRangeException(nameof(meterIndex));
        string serial = MeterIdentity.Serial(meterIndex);
        if (serial.Length < 3 || serial[0] > 127 || serial[1] > 127 ||
            !uint.TryParse(serial.AsSpan(2), NumberStyles.None, CultureInfo.InvariantCulture, out uint number))
            throw new NotSupportedException("Custom profile header requires a two-character ASCII meter prefix and numeric serial.");
        var header = new byte[11];
        header[0] = discriminator;
        header[1] = 1;
        header[2] = (byte)serial[0];
        header[3] = (byte)serial[1];
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4), number);
        return header;
    }
}
