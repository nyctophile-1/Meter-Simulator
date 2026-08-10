using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Testing;

/// <summary>
/// Saves and loads completed <see cref="TestRunReport"/>s from disk.
/// Each run is one JSON file: <c>../data/reports/&lt;runId&gt;.json</c>.
/// An index file keeps the list of run IDs for the Results viewer.
/// </summary>
public sealed class TestRunStore
{
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
        string path = ReportPath(report.RunId);
        File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOpts));
    }

    public TestRunReport? Load(string runId)
    {
        string path = ReportPath(runId);
        if (!File.Exists(path)) return null;

        try
        {
            return JsonSerializer.Deserialize<TestRunReport>(File.ReadAllText(path), JsonOpts);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load report {RunId}", runId);
            return null;
        }
    }

    /// <summary>Returns all saved reports, newest first.</summary>
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

    public string ReportPath(string runId) => Path.Combine(_folder, $"{runId}.json");

    public bool Exists(string runId) => File.Exists(ReportPath(runId));
}
