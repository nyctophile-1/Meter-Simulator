using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// File-backed <see cref="IBatchStore"/>: keeps the registry as a single human-readable JSON file.
/// Writes are atomic (temp file + rename) so a crash mid-save can never leave a half-written,
/// unparseable store. Chosen over a database because the registry is tiny and operator-driven —
/// per-meter DLMS state (millions of rows) is a separate concern and is not persisted here.
/// </summary>
public sealed class JsonBatchStore : IBatchStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _filePath;
    private readonly ILogger<JsonBatchStore>? _logger;
    private readonly object _fileLock = new();

    public JsonBatchStore(IOptions<PersistenceOptions> options, IHostEnvironment env, ILogger<JsonBatchStore> logger)
        : this(ResolvePath(options.Value, env), logger)
    {
    }

    /// <summary>Test/opt-in seam: point the store at an explicit absolute file path.</summary>
    public JsonBatchStore(string filePath, ILogger<JsonBatchStore>? logger = null)
    {
        _filePath = filePath;
        _logger = logger;
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
        _logger?.LogInformation("Batch store file: {Path}", _filePath);
    }

    public BatchStoreSnapshot Load()
    {
        lock (_fileLock)
        {
            if (!File.Exists(_filePath))
            {
                _logger?.LogInformation("No batch store at {Path} yet; starting with an empty registry.", _filePath);
                return new BatchStoreSnapshot();
            }

            string json = File.ReadAllText(_filePath);
            if (string.IsNullOrWhiteSpace(json))
            {
                return new BatchStoreSnapshot();
            }

            try
            {
                return JsonSerializer.Deserialize<BatchStoreSnapshot>(json, SerializerOptions) ?? new BatchStoreSnapshot();
            }
            catch (JsonException ex)
            {
                // Fail fast rather than silently starting empty: an empty registry would reset the
                // allocation cursor and reissue IPs/serials the HES already knows — the exact
                // collision this store exists to prevent. The operator must fix or remove the file.
                throw new InvalidOperationException(
                    $"Batch store '{_filePath}' is present but could not be parsed. Refusing to start with an " +
                    "empty registry (that would reuse already-issued meter addresses). Fix or remove the file.", ex);
            }
        }
    }

    public void Save(BatchStoreSnapshot snapshot)
    {
        lock (_fileLock)
        {
            string json = JsonSerializer.Serialize(snapshot, SerializerOptions);
            string tempPath = _filePath + ".tmp";

            // Write to a sibling temp file, then atomically swap it into place. If the process dies
            // mid-write, the previous good store is left untouched.
            File.WriteAllText(tempPath, json);
            File.Move(tempPath, _filePath, overwrite: true);
        }
    }

    private static string ResolvePath(PersistenceOptions options, IHostEnvironment env)
    {
        string folder = Path.IsPathRooted(options.Folder)
            ? options.Folder
            : Path.Combine(env.ContentRootPath, options.Folder);
        // Normalize so a "../data" relative folder collapses to a clean absolute path in logs/errors.
        return Path.GetFullPath(Path.Combine(folder, options.FileName));
    }
}
