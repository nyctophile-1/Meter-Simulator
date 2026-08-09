using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Settings;

/// <summary>
/// File-backed <see cref="IRuntimeConfigStore"/>, written next to the batch store in the
/// deploy-surviving data folder. Same atomic temp-file-plus-rename write as
/// <see cref="JsonBatchStore"/>, so a crash mid-save cannot leave an unparseable file.
///
/// Corruption policy is deliberately the OPPOSITE of the batch store. A bad batch file must stop
/// startup, because an empty registry would reissue meter addresses the HES already knows. A bad
/// config file is harmless: falling back to the configured defaults costs the operator a
/// re-entry in the UI, so it logs loudly and carries on rather than taking the simulator down
/// over a delay value.
/// </summary>
public sealed class JsonRuntimeConfigStore : IRuntimeConfigStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _filePath;
    private readonly ILogger<JsonRuntimeConfigStore>? _logger;
    private readonly object _fileLock = new();
    private MayaRuntimeConfig _document;

    public JsonRuntimeConfigStore(
        IOptions<PersistenceOptions> options,
        IHostEnvironment env,
        ILogger<JsonRuntimeConfigStore> logger)
        : this(ResolvePath(options.Value, env), logger)
    {
    }

    /// <summary>Test/opt-in seam: point the store at an explicit absolute file path.</summary>
    public JsonRuntimeConfigStore(string filePath, ILogger<JsonRuntimeConfigStore>? logger = null)
    {
        _filePath = filePath;
        _logger = logger;
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
        _document = Load();
        _logger?.LogInformation("Maya runtime config file: {Path}", _filePath);
    }

    public MayaRuntimeConfig Current => _document;

    public void Update(Action<MayaRuntimeConfig> mutate)
    {
        lock (_fileLock)
        {
            mutate(_document);

            try
            {
                string json = JsonSerializer.Serialize(_document, SerializerOptions);
                string tempPath = _filePath + ".tmp";
                File.WriteAllText(tempPath, json);
                File.Move(tempPath, _filePath, overwrite: true);
            }
            catch (Exception ex)
            {
                // In-memory change already applied above, so the operator's setting is live either
                // way. Losing only its durability is the better failure here.
                _logger?.LogError(ex, "Could not persist runtime config to {Path}; the change is " +
                    "active but will be lost on restart.", _filePath);
            }
        }
    }

    private MayaRuntimeConfig Load()
    {
        if (!File.Exists(_filePath))
        {
            return new MayaRuntimeConfig();
        }

        try
        {
            string json = File.ReadAllText(_filePath);
            return string.IsNullOrWhiteSpace(json)
                ? new MayaRuntimeConfig()
                : JsonSerializer.Deserialize<MayaRuntimeConfig>(json, SerializerOptions)
                  ?? new MayaRuntimeConfig();
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Maya runtime config file {Path} could not be read; falling back to " +
                "configured defaults. The file will be overwritten on the next settings change.", _filePath);
            return new MayaRuntimeConfig();
        }
    }

    private static string ResolvePath(PersistenceOptions options, IHostEnvironment env)
    {
        string folder = Path.IsPathRooted(options.Folder)
            ? options.Folder
            : Path.Combine(env.ContentRootPath, options.Folder);
        return Path.GetFullPath(Path.Combine(folder, options.RuntimeConfigFileName));
    }
}
