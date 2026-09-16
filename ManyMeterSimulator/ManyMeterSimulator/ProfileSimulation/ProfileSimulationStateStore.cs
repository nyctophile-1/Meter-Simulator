using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Gurux.DLMS.Objects;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.ProfileSimulation;

/// <summary>
/// Manages one durable, mutable XML model per simulated BATCH — not per meter. Generation is
/// deterministic and configured identically for every meter in a batch, so every meter produces
/// byte-identical simulated data; persisting one file per meter was pure duplication (it grew to
/// ~20,000 near-identical files in production — see ProfileStateRetentionService). The immutable
/// uploaded template is never modified. A working model is validated before it becomes current and
/// the previous valid XML is retained beside it for recovery.
/// </summary>
public sealed class ProfileSimulationStateStore
{
    private static readonly ConcurrentDictionary<string, object> FileLocks = new(StringComparer.OrdinalIgnoreCase);
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly ProfileSimulationOptions _options;
    private readonly string _root;
    private readonly ILogger<ProfileSimulationStateStore>? _logger;

    public ProfileSimulationStateStore(
        IOptions<ProfileSimulationOptions> options,
        IHostEnvironment environment,
        ILogger<ProfileSimulationStateStore> logger)
        : this(options.Value, ResolveRoot(options.Value, environment), logger)
    {
    }

    /// <summary>Test seam for an isolated state root.</summary>
    public ProfileSimulationStateStore(
        ProfileSimulationOptions options,
        string root,
        ILogger<ProfileSimulationStateStore>? logger = null)
    {
        _options = options;
        _root = Path.GetFullPath(root);
        _logger = logger;
        Directory.CreateDirectory(_root);
    }

    public bool Enabled => _options.Enabled;

    /// <summary>
    /// Resolves (and, on first use, creates) the batch's shared working XML. Existing state is
    /// never silently replaced when the source template changed; a migration needs an explicit
    /// decision. Idempotent and safe to call once per meter as each is materialized — every call
    /// for the same batch resolves to the same file.
    /// </summary>
    public bool TryGetOrCreate(
        MeterBatch batch,
        string sourceTemplatePath,
        out ProfileWorkingModel workingModel)
    {
        workingModel = default!;
        if (!_options.Enabled)
        {
            return false;
        }

        if (!File.Exists(sourceTemplatePath))
        {
            throw new FileNotFoundException("The source template required for profile simulation was not found.", sourceTemplatePath);
        }

        string batchFolder = Path.Combine(_root, $"batch-{batch.Id:D6}");
        string modelPath = Path.Combine(batchFolder, "model.xml");
        string previousPath = Path.Combine(batchFolder, "model.previous.xml");
        string metadataPath = Path.Combine(batchFolder, "metadata.json");
        string sourceHash = HashFile(sourceTemplatePath);
        var identity = new WorkingModelIdentity(
            batch.Id,
            batch.CreatedAtUtc,
            batch.StartIndex,
            batch.Count,
            Path.GetFileName(sourceTemplatePath),
            sourceHash);

        object fileLock = FileLocks.GetOrAdd(modelPath, _ => new object());
        lock (fileLock)
        {
            bool hasModel = File.Exists(modelPath);
            bool hasMetadata = File.Exists(metadataPath);
            if (hasModel != hasMetadata)
            {
                throw new InvalidOperationException(
                    $"Working profile state for batch {batch.Id} is incomplete at '{batchFolder}'. Refusing to overwrite it.");
            }

            if (!hasModel)
            {
                Directory.CreateDirectory(batchFolder);
                CopyValidatedAtomic(sourceTemplatePath, modelPath);
                WriteJsonAtomic(metadataPath, identity);
                _logger?.LogInformation("Created working profile XML for batch {Batch} at {Path}", batch.Id, modelPath);
            }
            else
            {
                WorkingModelIdentity? persisted = ReadIdentity(metadataPath);
                if (persisted is null || !persisted.Matches(identity))
                {
                    throw new InvalidOperationException(
                        $"Working profile state for batch {batch.Id} was created from a different batch definition or source template. " +
                        "Create an explicit migration or choose a new state folder; it will not be overwritten automatically.");
                }

                EnsureCurrentModelIsValid(modelPath, previousPath);
            }
        }

        workingModel = new ProfileWorkingModel(modelPath, previousPath, metadataPath, identity);
        return true;
    }

    /// <summary>
    /// Writes a complete XML to a sibling temporary file, validates it, retains the old good model,
    /// then replaces the current model. The write delegate must only write the supplied temp path.
    /// </summary>
    public void Save(ProfileWorkingModel model, Action<string> writeXml)
    {
        ArgumentNullException.ThrowIfNull(model);
        ArgumentNullException.ThrowIfNull(writeXml);

        object fileLock = FileLocks.GetOrAdd(model.ModelPath, _ => new object());
        lock (fileLock)
        {
            string folder = Path.GetDirectoryName(model.ModelPath)!;
            Directory.CreateDirectory(folder);
            string tempPath = Path.Combine(folder, $"model.{Guid.NewGuid():N}.tmp");
            string previousTempPath = Path.Combine(folder, $"model.previous.{Guid.NewGuid():N}.tmp");
            try
            {
                writeXml(tempPath);
                ValidateXml(tempPath);

                if (File.Exists(model.ModelPath))
                {
                    File.Copy(model.ModelPath, previousTempPath, overwrite: true);
                    ValidateXml(previousTempPath);
                    File.Move(previousTempPath, model.PreviousModelPath, overwrite: true);
                }

                File.Move(tempPath, model.ModelPath, overwrite: true);
            }
            finally
            {
                TryDelete(tempPath);
                TryDelete(previousTempPath);
            }
        }
    }

    /// <summary>
    /// Deletes any batch's working-state folder that nothing has written to in over
    /// <see cref="ProfileSimulationOptions.StateRetentionDays"/> days. This runs independently of
    /// <see cref="Enabled"/> — a folder left over from when the feature was on (or from a build that
    /// no longer references it) must still be reclaimed after the feature is toggled off or
    /// replaced, which is exactly the gap that let an earlier, per-meter build's state folder grow
    /// to ~20,000 files with nothing ever cleaning it up.
    /// </summary>
    /// <returns>The number of batch folders removed.</returns>
    public int PruneStale(DateTimeOffset utcNow)
    {
        if (!Directory.Exists(_root))
        {
            return 0;
        }

        DateTimeOffset cutoff = utcNow.ToUniversalTime().AddDays(-Math.Clamp(_options.StateRetentionDays, 1, 365));
        int removed = 0;

        foreach (string batchFolder in Directory.EnumerateDirectories(_root, "batch-*"))
        {
            string modelPath = Path.Combine(batchFolder, "model.xml");
            object fileLock = FileLocks.GetOrAdd(modelPath, _ => new object());
            lock (fileLock)
            {
                try
                {
                    if (LastActivityUtc(batchFolder) is DateTimeOffset lastActivity && lastActivity < cutoff)
                    {
                        Directory.Delete(batchFolder, recursive: true);
                        FileLocks.TryRemove(modelPath, out _);
                        removed++;
                        _logger?.LogInformation(
                            "Removed stale profile simulation state at {Path} (last written {LastActivity:u}, retention {RetentionDays}d)",
                            batchFolder, lastActivity, _options.StateRetentionDays);
                    }
                }
                catch (IOException exception)
                {
                    _logger?.LogWarning(exception, "Could not prune profile simulation state at {Path}", batchFolder);
                }
            }
        }

        return removed;
    }

    /// <summary>The most recent write across a batch's model, previous snapshot and metadata files.</summary>
    private static DateTimeOffset? LastActivityUtc(string batchFolder)
    {
        DateTimeOffset? latest = null;
        foreach (string file in Directory.EnumerateFiles(batchFolder))
        {
            DateTimeOffset writtenAt = File.GetLastWriteTimeUtc(file);
            if (latest is null || writtenAt > latest)
            {
                latest = writtenAt;
            }
        }

        return latest;
    }

    private static string ResolveRoot(ProfileSimulationOptions options, IHostEnvironment environment) =>
        Path.IsPathRooted(options.StateFolder)
            ? options.StateFolder
            : Path.Combine(environment.ContentRootPath, options.StateFolder);

    private static void CopyValidatedAtomic(string sourcePath, string destinationPath)
    {
        string tempPath = destinationPath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            File.Copy(sourcePath, tempPath, overwrite: false);
            ValidateXml(tempPath);
            File.Move(tempPath, destinationPath, overwrite: true);
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    private static void EnsureCurrentModelIsValid(string modelPath, string previousPath)
    {
        try
        {
            ValidateXml(modelPath);
        }
        catch (Exception currentException) when (File.Exists(previousPath))
        {
            try
            {
                ValidateXml(previousPath);
                string restoreTempPath = modelPath + $".{Guid.NewGuid():N}.restore";
                try
                {
                    File.Copy(previousPath, restoreTempPath, overwrite: false);
                    File.Move(restoreTempPath, modelPath, overwrite: true);
                }
                finally
                {
                    TryDelete(restoreTempPath);
                }
            }
            catch (Exception restoreException)
            {
                throw new InvalidOperationException(
                    $"Both current working XML '{modelPath}' and previous XML '{previousPath}' are invalid.",
                    new AggregateException(currentException, restoreException));
            }
        }
    }

    private static void ValidateXml(string path)
    {
        GXDLMSObjectCollection objects = GXDLMSObjectCollection.Load(path);
        if (objects.Count == 0)
        {
            throw new InvalidOperationException($"Working XML '{path}' contains no DLMS objects.");
        }
    }

    private static void WriteJsonAtomic<T>(string path, T value)
    {
        string tempPath = path + $".{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllText(tempPath, JsonSerializer.Serialize(value, JsonOptions));
            File.Move(tempPath, path, overwrite: true);
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    private static WorkingModelIdentity? ReadIdentity(string path)
    {
        try
        {
            return JsonSerializer.Deserialize<WorkingModelIdentity>(File.ReadAllText(path), JsonOptions);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException($"Working profile metadata '{path}' cannot be parsed.", exception);
        }
    }

    private static string HashFile(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private static void TryDelete(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}

/// <summary>Paths and immutable identity for one batch's current shared working model.</summary>
public sealed record ProfileWorkingModel(
    string ModelPath,
    string PreviousModelPath,
    string MetadataPath,
    WorkingModelIdentity Identity);

/// <summary>Detects accidental reuse of a working model after the batch definition/template changes.</summary>
public sealed record WorkingModelIdentity(
    int BatchId,
    DateTimeOffset BatchCreatedAtUtc,
    long BatchStartIndex,
    long BatchCount,
    string SourceTemplateFileName,
    string SourceTemplateSha256)
{
    public bool Matches(WorkingModelIdentity other) =>
        BatchId == other.BatchId
        && BatchCreatedAtUtc == other.BatchCreatedAtUtc
        && BatchStartIndex == other.BatchStartIndex
        && BatchCount == other.BatchCount
        && string.Equals(SourceTemplateFileName, other.SourceTemplateFileName, StringComparison.OrdinalIgnoreCase)
        && string.Equals(SourceTemplateSha256, other.SourceTemplateSha256, StringComparison.Ordinal);
}
