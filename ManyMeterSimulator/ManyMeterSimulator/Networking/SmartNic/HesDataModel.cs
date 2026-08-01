namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>
/// HES's meter data model, loaded from CSV exports of its own tables. This is what lets the smart
/// NIC answer a custom-channel request: it says which OBIS to read for each field, and how to lay
/// the results out on the wire.
///
/// Four tables, two lookups:
/// <code>
///   MagicNumberMapping      MagicNumber ⇄ TemplateId        (the 12-byte header's key)
///   MeterTemplate           TemplateId  → framing + which profile template per profile kind
///   MeterTemplateDetail     ProfileTemplateId + ProfileType → ordered fields (the byte layout)
///   ProfileAttributeMapping Profile + Category + Parameter  → OBIS + attribute (the read plan)
/// </code>
///
/// Loaded as-is, with no cross-table validation. A magic number pointing at a template that has
/// since been edited to a different NIC type is ordinary drift, not corruption — the row simply
/// never gets looked up, and inventing a failure for it would be worse than ignoring it.
/// </summary>
public sealed class HesDataModel
{
    private readonly Dictionary<uint, int> _templateByMagic = new();
    private readonly Dictionary<int, uint> _magicByTemplate = new();
    private readonly Dictionary<int, MeterTemplateRow> _templates = new();
    private readonly Dictionary<(int ProfileTemplateId, string ProfileType), List<TemplateField>> _fields = new();
    private readonly Dictionary<(int Profile, string Category, string Parameter), AttributeMapping> _attributes = new();

    public int MagicNumberCount => _templateByMagic.Count;

    public int TemplateCount => _templates.Count;

    public int FieldListCount => _fields.Count;

    public int AttributeCount => _attributes.Count;

    internal void AddMagic(uint magicNumber, int templateId)
    {
        _templateByMagic[magicNumber] = templateId;

        // Reverse direction is what the simulator actually needs: we ARE the meter, so we emit a
        // magic number chosen by our template. Keep the first mapping for a template — later rows
        // are historical re-assignments.
        _magicByTemplate.TryAdd(templateId, magicNumber);
    }

    internal void AddTemplate(MeterTemplateRow row) => _templates[row.Id] = row;

    internal void AddField(int profileTemplateId, string profileType, TemplateField field)
    {
        if (!_fields.TryGetValue((profileTemplateId, profileType), out List<TemplateField>? list))
        {
            list = new List<TemplateField>();
            _fields[(profileTemplateId, profileType)] = list;
        }

        list.Add(field);
    }

    internal void AddAttribute(int profile, string category, string parameter, AttributeMapping mapping) =>
        _attributes[(profile, category, parameter)] = mapping;

    /// <summary>Sorts every field list by SerialNumber. The order IS the wire layout.</summary>
    internal void Freeze()
    {
        foreach (List<TemplateField> list in _fields.Values)
        {
            list.Sort((a, b) => a.SerialNumber.CompareTo(b.SerialNumber));
        }
    }

    public bool TryGetTemplateByMagic(uint magicNumber, out int templateId) =>
        _templateByMagic.TryGetValue(magicNumber, out templateId);

    /// <summary>The magic number to put in our response header for this template, if it has one.</summary>
    public bool TryGetMagicForTemplate(int templateId, out uint magicNumber) =>
        _magicByTemplate.TryGetValue(templateId, out magicNumber);

    public bool TryGetTemplate(int templateId, out MeterTemplateRow template) =>
        _templates.TryGetValue(templateId, out template!);

    /// <summary>
    /// The ordered field list for one profile of one template — the response layout.
    /// <paramref name="profileType"/> is the composite discriminator, e.g. "BLOCK_CUSTOM_PULL_3P".
    /// </summary>
    public IReadOnlyList<TemplateField> GetFields(int profileTemplateId, string profileType) =>
        _fields.TryGetValue((profileTemplateId, profileType), out List<TemplateField>? list)
            ? list
            : Array.Empty<TemplateField>();

    /// <summary>Where a field's value comes from in the meter — the smart NIC's read plan.</summary>
    public bool TryGetAttribute(int profile, string category, string parameter, out AttributeMapping mapping) =>
        _attributes.TryGetValue((profile, category, parameter), out mapping!);
}

/// <summary>
/// A row of HES's MeterTemplate. The header lengths and payload types are what select the framing:
/// <c>PullHeaderLength</c> 5 = Wirepas DLMS, 6 = direct 4G, 7 = Kmesh, 10 = custom (old header),
/// 12 = custom (new header, carries a MagicNumber), 0 = no NIC header.
/// </summary>
public readonly record struct MeterTemplateRow(
    int Id,
    string TemplateName,
    int PushHeaderLength,
    int PullHeaderLength,
    int PushPayloadType,
    int PullPayloadType,
    bool IsFG23,
    int? BlockTemplateId,
    int? DailyTemplateId,
    int? BillTemplateId,
    int? InstantTemplateId,
    int? EventTemplateId,
    int? MiscTemplateId)
{
    /// <summary>The new 12-byte custom header is the only one carrying a magic number.</summary>
    public bool UsesNewHeader => PullHeaderLength == 12;

    /// <summary>Node id width, per HES's NodeIdBytesBasedOnTemplate.</summary>
    public int NodeIdBytes => PullHeaderLength == 12 || IsFG23 ? 4 : 3;
}

/// <summary>
/// One field in a profile's layout. <see cref="SerialNumber"/> is its position — the row order in
/// HES's table is the byte order on the wire, so this is the single most load-bearing value here.
/// </summary>
public readonly record struct TemplateField(
    int SerialNumber,
    string ParameterName,
    string DataType,
    int Scalar,
    int Profile,
    string MeterCategory,
    int CommandTypeId);

/// <summary>Where a field's value lives in the meter's DLMS object model.</summary>
public readonly record struct AttributeMapping(string ObisCode, int AttributeIndex);
