using System.Globalization;
using System.Text;

namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>
/// Loads <see cref="HesDataModel"/> from CSV exports of HES's tables (see
/// <c>KimbalSpecifics/DataModel/</c>).
///
/// Column lookup is BY NAME, not by position: these are hand-run exports, and a column added or
/// reordered upstream would otherwise silently shift every field — the same class of failure as
/// getting a header width wrong, and just as hard to spot afterwards.
/// </summary>
public sealed class HesDataModelLoader
{
    private readonly ILogger<HesDataModelLoader> _logger;

    public HesDataModelLoader(ILogger<HesDataModelLoader> logger) => _logger = logger;

    /// <summary>
    /// Loads whichever of the four CSVs are present. A missing file is not fatal — the model is
    /// only consulted by the custom channel, so a deployment that never uses it need not ship the
    /// exports at all.
    /// </summary>
    public HesDataModel Load(string folder)
    {
        var model = new HesDataModel();

        if (!Directory.Exists(folder))
        {
            _logger.LogInformation("No HES data model at {Folder}; the custom channel will be unavailable.", folder);
            return model;
        }

        LoadMagicNumbers(model, Path.Combine(folder, "MagicNumberMapping.csv"));
        LoadTemplates(model, Path.Combine(folder, "MeterTemplate.csv"));
        LoadFields(model, Path.Combine(folder, "MeterTemplateDetail.csv"));
        LoadAttributes(model, Path.Combine(folder, "ProfileAttributeMapping.csv"));

        model.Freeze();

        _logger.LogInformation(
            "HES data model loaded from {Folder}: {Magic} magic numbers, {Templates} templates, " +
            "{FieldLists} profile layouts, {Attributes} attribute mappings",
            folder, model.MagicNumberCount, model.TemplateCount, model.FieldListCount, model.AttributeCount);

        return model;
    }

    private void LoadMagicNumbers(HesDataModel model, string path) =>
        ForEachRow(path, row =>
        {
            if (TryUInt(row, "MagicNumber", out uint magic) && TryInt(row, "TemplateId", out int templateId))
            {
                model.AddMagic(magic, templateId);
            }
        });

    private void LoadTemplates(HesDataModel model, string path) =>
        ForEachRow(path, row =>
        {
            if (!TryInt(row, "Id", out int id))
            {
                return;
            }

            model.AddTemplate(new MeterTemplateRow(
                id,
                Get(row, "TemplateName"),
                Int(row, "PushHeaderLength"),
                Int(row, "PullHeaderLength"),
                Int(row, "PushPayloadType"),
                Int(row, "PullPayloadType"),
                Get(row, "IsFG23") is "1" or "True" or "true",
                NullableInt(row, "BlockTemplateId"),
                NullableInt(row, "DailyTemplateId"),
                NullableInt(row, "BillTemplateId"),
                NullableInt(row, "InstantTemplateId"),
                NullableInt(row, "EventTemplateId"),
                NullableInt(row, "MiscTemplateId")));
        });

    private void LoadFields(HesDataModel model, string path) =>
        ForEachRow(path, row =>
        {
            if (!TryInt(row, "ProfileTemplateId", out int profileTemplateId))
            {
                return;
            }

            string profileType = Get(row, "ProfileType");
            if (profileType.Length == 0)
            {
                return;
            }

            model.AddField(profileTemplateId, profileType, new TemplateField(
                Int(row, "SerialNumber"),
                Get(row, "ParameterName"),
                Get(row, "DataType"),
                Int(row, "Scalar"),
                Int(row, "Profile"),
                Get(row, "MeterCategory"),
                Int(row, "CommandTypeId")));
        });

    private void LoadAttributes(HesDataModel model, string path) =>
        ForEachRow(path, row =>
        {
            string parameter = Get(row, "Attribute");
            if (parameter.Length == 0)
            {
                return;
            }

            model.AddAttribute(
                Int(row, "ProfileType"),          // int here; the composite string lives in MeterTemplateDetail
                Get(row, "Category"),
                parameter,
                new AttributeMapping(Get(row, "ObisCode"), Int(row, "AttributeIndex")));
        });

    private void ForEachRow(string path, Action<IReadOnlyDictionary<string, string>> handle)
    {
        if (!File.Exists(path))
        {
            _logger.LogDebug("HES data model: {File} not present, skipping.", Path.GetFileName(path));
            return;
        }

        int rows = 0;
        using var reader = new StreamReader(path, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);

        string[]? header = ReadRow(reader);
        if (header is null)
        {
            return;
        }

        // A UTF-8 BOM survives into the first header cell and would break the name lookup.
        header[0] = header[0].TrimStart('﻿');

        var index = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < header.Length; i++)
        {
            index[header[i]] = i;
        }

        var view = new RowView(index);
        while (ReadRow(reader) is { } cells)
        {
            view.Cells = cells;
            handle(view);
            rows++;
        }

        _logger.LogDebug("HES data model: {File} -> {Rows} rows", Path.GetFileName(path), rows);
    }

    /// <summary>
    /// Reads one CSV record, honouring quoted fields — including embedded commas, doubled quotes
    /// and newlines inside a quoted value, all of which appear in these exports.
    /// </summary>
    private static string[]? ReadRow(TextReader reader)
    {
        if (reader.Peek() < 0)
        {
            return null;
        }

        var cells = new List<string>();
        var cell = new StringBuilder();
        bool quoted = false;

        while (true)
        {
            int read = reader.Read();
            if (read < 0)
            {
                cells.Add(cell.ToString());
                return cells.ToArray();
            }

            var c = (char)read;

            if (quoted)
            {
                if (c == '"')
                {
                    if (reader.Peek() == '"')
                    {
                        reader.Read();
                        cell.Append('"');
                    }
                    else
                    {
                        quoted = false;
                    }
                }
                else
                {
                    cell.Append(c);
                }

                continue;
            }

            switch (c)
            {
                case '"':
                    quoted = true;
                    break;
                case ',':
                    cells.Add(cell.ToString());
                    cell.Clear();
                    break;
                case '\r':
                    break;
                case '\n':
                    cells.Add(cell.ToString());
                    return cells.ToArray();
                default:
                    cell.Append(c);
                    break;
            }
        }
    }

    private static string Get(IReadOnlyDictionary<string, string> row, string column) =>
        row.TryGetValue(column, out string? value) ? value.Trim() : string.Empty;

    private static bool TryInt(IReadOnlyDictionary<string, string> row, string column, out int value) =>
        int.TryParse(Get(row, column), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);

    private static bool TryUInt(IReadOnlyDictionary<string, string> row, string column, out uint value) =>
        uint.TryParse(Get(row, column), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);

    private static int Int(IReadOnlyDictionary<string, string> row, string column) =>
        TryInt(row, column, out int value) ? value : 0;

    private static int? NullableInt(IReadOnlyDictionary<string, string> row, string column) =>
        TryInt(row, column, out int value) ? value : null;

    /// <summary>Reuses one dictionary view across rows — 145k rows makes per-row allocation matter.</summary>
    private sealed class RowView : IReadOnlyDictionary<string, string>
    {
        private readonly Dictionary<string, int> _index;

        public RowView(Dictionary<string, int> index) => _index = index;

        public string[] Cells { get; set; } = Array.Empty<string>();

        public bool TryGetValue(string key, out string value)
        {
            if (_index.TryGetValue(key, out int i) && i < Cells.Length)
            {
                value = Cells[i];
                return true;
            }

            value = string.Empty;
            return false;
        }

        public string this[string key] => TryGetValue(key, out string v) ? v : throw new KeyNotFoundException(key);
        public IEnumerable<string> Keys => _index.Keys;
        public IEnumerable<string> Values => _index.Values.Select(i => Cells[i]);
        public int Count => _index.Count;
        public bool ContainsKey(string key) => _index.ContainsKey(key);
        public IEnumerator<KeyValuePair<string, string>> GetEnumerator() =>
            _index.Select(kv => new KeyValuePair<string, string>(kv.Key, Cells[kv.Value])).GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
