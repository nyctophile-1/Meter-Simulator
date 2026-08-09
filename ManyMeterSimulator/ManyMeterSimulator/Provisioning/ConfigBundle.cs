using System.Text.Json;
using System.Text.Json.Serialization;
using ManyMeterSimulator.Networking.Registry;

namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// One portable file carrying the whole operator-set configuration: every batch and every network
/// endpoint. This is the migration unit — moving a fleet between deployments is otherwise a manual
/// re-registration of every meter with the HES, which is the pain this exists to remove.
///
/// <para>
/// Batches and endpoints travel together on purpose. A batch is bound to a broker by key, so a
/// bundle that carried batches without their endpoints would land as bindings pointing at brokers
/// that are not there. One file, one import, both halves.
/// </para>
///
/// <para>
/// <b>Broker passwords are in plaintext here</b> (see <see cref="NetworkRegistry.Snapshot"/>): the
/// file is meant to be portable, so it cannot depend on the source host's encryption keys. The
/// destination re-encrypts on import. Treat an exported bundle as a secret.
/// </para>
/// </summary>
public sealed record ConfigBundle
{
    /// <summary>Bumped only if a future change needs migration logic on import.</summary>
    public int BundleVersion { get; init; } = 1;

    public DateTimeOffset ExportedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Free-text, e.g. the source host or environment — for the operator's own bookkeeping.</summary>
    public string? ExportedFrom { get; init; }

    public BatchStoreSnapshot Batches { get; init; } = new();

    public NetworkRegistrySnapshot Network { get; init; } = new();
}

/// <summary>
/// Exports and imports a <see cref="ConfigBundle"/> across the two registries.
///
/// <para>
/// Import order is deliberate: network first, then batches, so that by the time a batch is loaded
/// its bound broker already exists and the reconcile pass can bring its client up immediately. The
/// reverse order would flash every batch as "broker MISSING" until the endpoints landed.
/// </para>
/// </summary>
public sealed class ConfigBundleService
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly MeterRegistry _batches;
    private readonly NetworkRegistry _network;

    public ConfigBundleService(MeterRegistry batches, NetworkRegistry network)
    {
        _batches = batches;
        _network = network;
    }

    public string Export(string? exportedFrom = null)
    {
        var bundle = new ConfigBundle
        {
            ExportedFrom = exportedFrom,
            Batches = _batches.Snapshot(),
            Network = _network.Snapshot(),
        };

        return JsonSerializer.Serialize(bundle, Options);
    }

    /// <summary>
    /// Parses and validates a bundle WITHOUT applying it, returning what it would import. Lets the
    /// UI show the operator exactly what a file contains — and reject a malformed one — before the
    /// irreversible "replace everything" confirmation.
    /// </summary>
    public ConfigImportSummary Preview(string json) => Summarize(Parse(json));

    /// <summary>
    /// Parses and applies a bundle, replacing ALL current batches and endpoints. Throws
    /// <see cref="ArgumentException"/> with a readable reason if the JSON is not a bundle — the
    /// caller surfaces that to the operator rather than half-applying anything.
    /// </summary>
    public ConfigImportSummary Import(string json)
    {
        ConfigBundle bundle = Parse(json);

        // Network first so batch bindings resolve on the way in (see the class remarks).
        _network.ImportSnapshot(bundle.Network);
        _batches.ImportSnapshot(bundle.Batches);

        return Summarize(bundle);
    }

    private static ConfigBundle Parse(string json)
    {
        ConfigBundle? bundle;
        try
        {
            bundle = JsonSerializer.Deserialize<ConfigBundle>(json, Options);
        }
        catch (JsonException ex)
        {
            throw new ArgumentException($"Not a valid configuration file: {ex.Message}");
        }

        if (bundle is null)
        {
            throw new ArgumentException("The file is empty or not a configuration bundle.");
        }

        Validate(bundle);
        return bundle;
    }

    private static ConfigImportSummary Summarize(ConfigBundle bundle) => new(
        bundle.Batches.Batches.Count,
        bundle.Network.Brokers.Count,
        bundle.Network.PushTargets.Count,
        bundle.ExportedFrom,
        bundle.ExportedAtUtc);

    /// <summary>
    /// The NAME is the identity of every object here — it is how a batch on one deployment is
    /// recognised as the same batch on another (numeric ids are per-deployment and meaningless
    /// across a move). So a bundle with two batches of the same name, or an endpoint key reused,
    /// is ambiguous and rejected before anything is applied — rather than silently keeping one.
    /// </summary>
    private static void Validate(ConfigBundle bundle)
    {
        string? dupeBatch = bundle.Batches.Batches
            .GroupBy(b => b.Name, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(g => g.Count() > 1)?.Key;
        if (dupeBatch is not null)
        {
            throw new ArgumentException(
                $"The file has more than one batch named '{dupeBatch}'. Batch names are the identity " +
                "used to migrate config, so they must be unique.");
        }

        List<string> endpointKeys = bundle.Network.Brokers.Select(b => b.Key)
            .Concat(bundle.Network.PushTargets.Select(p => p.Key))
            .ToList();
        string? dupeKey = endpointKeys
            .GroupBy(k => k, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(g => g.Count() > 1)?.Key;
        if (dupeKey is not null)
        {
            throw new ArgumentException(
                $"The file has more than one network endpoint named '{dupeKey}'. Endpoint names must " +
                "be unique across brokers and push targets.");
        }
    }
}

/// <summary>What an import applied — shown back to the operator so they can confirm it landed.</summary>
public readonly record struct ConfigImportSummary(
    int Batches, int Brokers, int PushTargets, string? ExportedFrom, DateTimeOffset ExportedAtUtc);
