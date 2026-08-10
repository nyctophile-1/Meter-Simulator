using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Testing;

public sealed class JsonTestPlanStore : ITestPlanStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _path;
    private readonly ILogger<JsonTestPlanStore> _logger;

    public JsonTestPlanStore(IOptions<PersistenceOptions> opts, IHostEnvironment env, ILogger<JsonTestPlanStore> logger)
    {
        string folder = opts.Value.Folder;
        string resolved = Path.IsPathRooted(folder)
            ? folder
            : Path.Combine(env.ContentRootPath, folder);
        Directory.CreateDirectory(resolved);
        _path = Path.Combine(resolved, opts.Value.TestPlansFileName);
        _logger = logger;
    }

    public IReadOnlyList<TestPlan> Load()
    {
        if (!File.Exists(_path))
        {
            return Array.Empty<TestPlan>();
        }

        try
        {
            string json = File.ReadAllText(_path);
            return JsonSerializer.Deserialize<List<TestPlan>>(json, Options) ?? new();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load test plans from {Path}", _path);
            return Array.Empty<TestPlan>();
        }
    }

    public void Save(IReadOnlyList<TestPlan> plans)
    {
        try
        {
            File.WriteAllText(_path, JsonSerializer.Serialize(plans, Options));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save test plans to {Path}", _path);
        }
    }
}
