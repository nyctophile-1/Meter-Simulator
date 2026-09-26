using System.Collections.Concurrent;
using System.Security.Cryptography;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;
using MeterSimulator.Fota;
using MeterSimulator.Models;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Fota;

public sealed record FotaProgress(long Index, string Serial, string Image, int Received, int Total,
    string Status, string CurrentVersion, string TargetVersion, string LastFailure);

public sealed class FotaService
{
    private readonly TemplateRegistry _templates;
    private readonly FotaLimits _limits;
    private readonly FotaStateStore _store;
    private readonly string _settingsPath;
    private readonly object _settingsGate = new();
    private Dictionary<string, FotaSettings> _settings;
    private readonly ConcurrentDictionary<string, (string Hash, bool Supported, string Version)> _capabilities = new();

    public FotaService(TemplateRegistry templates, IOptions<PersistenceOptions> persistence,
        IOptions<FotaLimits> limits, IHostEnvironment environment)
        : this(templates, Path.GetFullPath(persistence.Value.Folder, environment.ContentRootPath), limits.Value)
    {
    }

    public FotaService(TemplateRegistry templates, string dataRoot, FotaLimits limits)
    {
        _templates = templates;
        _limits = limits;
        limits.Validate();
        _store = new FotaStateStore(Path.Combine(dataRoot, "fota", "meters"), limits);
        _settingsPath = Path.Combine(dataRoot, "fota", "settings.json");
        _settings = File.Exists(_settingsPath)
            ? FotaStateStore.ReadDocument<Dictionary<string, FotaSettings>>(_settingsPath)
            : new();

        foreach (FotaSettings setting in _settings.Values)
        {
            setting.Validate();
        }
    }

    public bool Supported(MeterBatch batch) => Capability(batch).Supported;

    private (string Hash, bool Supported, string Version) Capability(MeterBatch batch)
    {
        string path = _templates.ResolveOrThrow(batch.TemplateName);
        return _capabilities.GetOrAdd(path, file =>
        {
            var objects = TemplateModelCache.Shared.Get(file);
            var image = objects.FindByLN(ObjectType.ImageTransfer, DLMSServerSession.ImageTransferObis);
            var version = objects.FindByLN(ObjectType.Data, DLMSServerSession.FirmwareVersionObis) as GXDLMSData;
            string initial = version?.Value is byte[] bytes
                ? System.Text.Encoding.UTF8.GetString(bytes)
                : Convert.ToString(version?.Value) ?? "";
            using var stream = File.OpenRead(file);
            return (Convert.ToHexString(SHA256.HashData(stream)), image is not null && version is not null, initial);
        });
    }

    private string BatchKey(MeterBatch batch) => $"{batch.Id}:{batch.CreatedAtUtc.UtcTicks}:{batch.StartIndex}:{batch.Count}:{Capability(batch).Hash}";
    private string MeterKey(MeterBatch batch, long index) => $"{BatchKey(batch)}:{index}";

    public FotaSettings Settings(MeterBatch batch, long? index = null)
    {
        ValidateIndex(batch, index);
        string key = index.HasValue ? MeterKey(batch, index.Value) : BatchKey(batch);
        lock (_settingsGate)
        {
            if (_settings.TryGetValue(key, out FotaSettings? exact))
            {
                return exact with { };
            }

            if (index.HasValue && _settings.TryGetValue(BatchKey(batch), out FotaSettings? fallback))
            {
                return fallback with { };
            }

            return new();
        }
    }

    public void SaveSettings(MeterBatch batch, long? index, FotaSettings settings)
    {
        settings.Validate();
        ValidateIndex(batch, index);
        if (settings.Enabled && !Supported(batch))
        {
            throw new ArgumentException("This template needs image-transfer 0.0.44.0.0.255 and firmware-version 1.0.0.2.0.255 objects.");
        }

        string key = index.HasValue ? MeterKey(batch, index.Value) : BatchKey(batch);
        lock (_settingsGate)
        {
            var next = new Dictionary<string, FotaSettings>(_settings) { [key] = settings with { } };
            FotaStateStore.WriteAtomic(_settingsPath, next);
            _settings = next;
        }
    }

    public void RemoveOverride(MeterBatch batch, long index)
    {
        ValidateIndex(batch, index);
        lock (_settingsGate)
        {
            var next = new Dictionary<string, FotaSettings>(_settings);
            next.Remove(MeterKey(batch, index));
            FotaStateStore.WriteAtomic(_settingsPath, next);
            _settings = next;
        }
    }

    public IFotaMeter? Bind(MeterBatch batch, long index)
    {
        ValidateIndex(batch, index);
        return Supported(batch)
            ? new FotaMeter(_store, MeterKey(batch, index), () => Settings(batch, index), _limits)
            : null;
    }

    public IReadOnlyList<FotaProgress> Progress(MeterBatch batch, long firstIndex, int count = 50)
    {
        var rows = new List<FotaProgress>();
        long first = Math.Max(batch.StartIndex, firstIndex);
        long last = Math.Min(batch.EndIndex, first + Math.Clamp(count, 1, 50) - 1);
        for (long index = first; index <= last; index++)
        {
            FotaProgress row = _store.Read(MeterKey(batch, index), state => new FotaProgress(
                index, MeterIdentity.Serial(index), state.ImageId, state.Blocks.Count, state.TotalBlocks,
                state.Status.ToString(), state.ActiveVersion ?? Capability(batch).Version,
                state.Settings?.TargetVersion ?? Settings(batch, index).TargetVersion, state.LastFailure));
            rows.Add(row);
        }

        return rows;
    }

    public void Reset(MeterBatch batch, long index)
    {
        ValidateIndex(batch, index);
        ErrorCode result = _store.Change(MeterKey(batch, index), _ => new(ErrorCode.Ok, new FotaEvent { Kind = "reset" }));
        if (result != ErrorCode.Ok)
        {
            throw new IOException("The reset could not be persisted; transfer state was not acknowledged as reset.");
        }
    }

    private static void ValidateIndex(MeterBatch batch, long? index)
    {
        if (index.HasValue && (index < batch.StartIndex || index > batch.EndIndex))
        {
            throw new ArgumentException("Meter index is outside the selected batch.");
        }
    }
}
