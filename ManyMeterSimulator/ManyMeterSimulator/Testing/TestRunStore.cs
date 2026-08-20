using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Testing;

public sealed class TestRunStore
{
    private const int MaxPerPlan = 20;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _folder;
    private readonly ILogger<TestRunStore> _logger;

    public TestRunStore(IOptions<PersistenceOptions> opts, IHostEnvironment env, ILogger<TestRunStore> logger)
    {
        string dataFolder = opts.Value.Folder;
        string resolved = Path.IsPathRooted(dataFolder)
            ? dataFolder
            : Path.Combine(env.ContentRootPath, dataFolder);
        _folder = Path.Combine(resolved, opts.Value.ReportsFolderName);
        Directory.CreateDirectory(_folder);
        _logger = logger;
    }

    public string ReportsFolder => _folder;

    public void Save(TestRunReport report)
    {
        string path = ReportPath(report);
        File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOpts));
        EnforceLimit();
    }

    public TestRunReport? Load(string runId)
    {
        // try exact name first, then scan (label may differ)
        string exact = Path.Combine(_folder, $"{runId}.json");
        string? found = File.Exists(exact) ? exact : FindFileByRunId(runId);
        if (found is null) return null;

        try { return JsonSerializer.Deserialize<TestRunReport>(File.ReadAllText(found), JsonOpts); }
        catch (Exception ex) { _logger.LogError(ex, "Failed to load report {RunId}", runId); return null; }
    }

    public bool Rename(string runId, string label, out string? error)
    {
        error = null;
        string? path = FindFileByRunId(runId);
        if (path is null) { error = "Run report was not found."; return false; }
        try
        {
            JsonObject? node = JsonNode.Parse(File.ReadAllText(path))?.AsObject();
            if (node is null) { error = "Run report could not be read."; return false; }
            node[nameof(TestRunReport.RunLabel)] = label.Trim();
            File.WriteAllText(path, node.ToJsonString(JsonOpts));
            return true;
        }
        catch (Exception ex) { _logger.LogError(ex, "Failed to rename report {RunId}", runId); error = ex.Message; return false; }
    }

    public bool Delete(string runId, out string? error)
    {
        error = null;
        string? path = FindFileByRunId(runId);
        if (path is null) { error = "Run report was not found."; return false; }
        try { File.Delete(path); return true; }
        catch (Exception ex) { _logger.LogError(ex, "Failed to delete report {RunId}", runId); error = ex.Message; return false; }
    }

    public IReadOnlyList<TestRunReport> LoadAll()
    {
        return Directory.GetFiles(_folder, "*.json")
            .Select(path =>
            {
                try { return JsonSerializer.Deserialize<TestRunReport>(File.ReadAllText(path), JsonOpts); }
                catch { return null; }
            })
            .Where(r => r is not null)
            .Select(r => r!)
            .OrderByDescending(r => r.StartUtc)
            .ToList();
    }

    /// <summary>
    /// Returns the filename that would be used for a new save — useful for the download endpoint
    /// which needs to reconstruct the file path from just the runId.
    /// </summary>
    public string? FindFileByRunId(string runId)
    {
        return Directory.GetFiles(_folder, $"*{runId}*.json").FirstOrDefault();
    }

    private void EnforceLimit()
    {
        try
        {
            var toDelete = Directory.GetFiles(_folder, "*.json")
                .Select(p => (path: p, report: TryDeserialize(p)))
                .Where(x => x.report is not null)
                .Select(x => (x.path, Report: x.report!))
                .GroupBy(x => x.Report.PlanId)
                .SelectMany(g => g.OrderByDescending(x => x.Report.StartUtc).Skip(MaxPerPlan))
                .Select(x => x.path)
                .ToList();

            foreach (string path in toDelete)
                File.Delete(path);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to enforce {Max} per-plan result limit", MaxPerPlan);
        }
    }

    private TestRunReport? TryDeserialize(string path)
    {
        try { return JsonSerializer.Deserialize<TestRunReport>(File.ReadAllText(path), JsonOpts); }
        catch { return null; }
    }

    public string ReportPath(TestRunReport report)
    {
        string ts = report.StartUtc.LocalDateTime.ToString("yyyyMMddHHmm");
        string envPart = report.EnvironmentKeys.Count > 0
            ? "_" + string.Join("+", report.EnvironmentKeys.Select(e => Slugify(e)[..Math.Min(12, Slugify(e).Length)]))
            : "";
        string labelPart = string.IsNullOrWhiteSpace(report.RunLabel) ? "" : Slugify(report.RunLabel) + "_";
        return Path.Combine(_folder, $"{labelPart}{envPart}_{ts}_{report.RunId}.json");
    }

    // Keep for backward-compat (e.g. Load uses FindFileByRunId which scans by runId)
    public string ReportPath(string runId, string? label = null)
    {
        string slug = string.IsNullOrWhiteSpace(label) ? runId : $"{Slugify(label)}-{runId}";
        return Path.Combine(_folder, $"{slug}.json");
    }

    private static string Slugify(string s) =>
        new string(s.ToLowerInvariant()
            .Select(c => char.IsLetterOrDigit(c) ? c : '-')
            .ToArray())
        .Trim('-')[..Math.Min(40, s.Length)];
}
