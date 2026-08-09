using System.Text.Json;
using System.Text.Json.Serialization;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Settings;

namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// Portable export/import of each setup page's own configuration, one file per page.
///
/// <para>
/// Three separate files rather than one bundle, so each setup page owns its own migration and an
/// operator moves exactly the piece they mean to. The trade-off is a cross-file dependency —
/// batches are bound to brokers by name — so when moving a fleet whole, import <b>network before
/// batches</b>, or the batches land showing their broker as MISSING until the endpoints arrive.
/// </para>
///
/// <para>
/// Every file is tagged with its <see cref="ConfigFile{T}.Kind"/>, so importing a network file on
/// the batch page (or vice versa) is rejected with a clear message instead of silently wiping the
/// wrong thing. Broker passwords in the network file are plaintext for portability — see
/// <see cref="NetworkRegistry.Snapshot"/>.
/// </para>
/// </summary>
public sealed class ConfigBundleService
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public const string BatchesKind = "maya.batches";
    public const string NetworkKind = "maya.network";
    public const string BadCommKind = "maya.badcomm";

    private readonly MeterRegistry _batches;
    private readonly NetworkRegistry _network;
    private readonly BadCommSettings _badComm;
    private readonly NetworkDelaySettings _networkDelay;

    public ConfigBundleService(
        MeterRegistry batches,
        NetworkRegistry network,
        BadCommSettings badComm,
        NetworkDelaySettings networkDelay)
    {
        _batches = batches;
        _network = network;
        _badComm = badComm;
        _networkDelay = networkDelay;
    }

    // ── Batches ────────────────────────────────────────────────────────────────────────────────

    public string ExportBatches(string? from = null) =>
        Serialize(BatchesKind, from, _batches.Snapshot());

    /// <summary>Parses and validates a batches file without applying it — for the confirm dialog.</summary>
    public int PreviewBatches(string json) => Parse<BatchStoreSnapshot>(json, BatchesKind).Batches.Count;

    public int ImportBatches(string json)
    {
        BatchStoreSnapshot snapshot = Parse<BatchStoreSnapshot>(json, BatchesKind);
        ValidateUniqueBatchNames(snapshot);
        _batches.ImportSnapshot(snapshot);
        return snapshot.Batches.Count;
    }

    // ── Network ────────────────────────────────────────────────────────────────────────────────

    public string ExportNetwork(string? from = null) =>
        Serialize(NetworkKind, from, _network.Snapshot());

    public (int Brokers, int PushTargets) PreviewNetwork(string json)
    {
        NetworkRegistrySnapshot s = Parse<NetworkRegistrySnapshot>(json, NetworkKind);
        return (s.Brokers.Count, s.PushTargets.Count);
    }

    public (int Brokers, int PushTargets) ImportNetwork(string json)
    {
        NetworkRegistrySnapshot snapshot = Parse<NetworkRegistrySnapshot>(json, NetworkKind);
        ValidateUniqueEndpointKeys(snapshot);
        _network.ImportSnapshot(snapshot);
        return (snapshot.Brokers.Count, snapshot.PushTargets.Count);
    }

    // ── BadComm (field-impairment knobs: the bad-comm config plus the network delay) ─────────────

    public string ExportBadComm(string? from = null) =>
        Serialize(BadCommKind, from, new BadCommFile
        {
            BadComm = _badComm.Snapshot(),
            NetworkDelay = new DelayRange { LowerMs = _networkDelay.Current.LowerMs, UpperMs = _networkDelay.Current.UpperMs },
        });

    public void PreviewBadComm(string json) => Parse<BadCommFile>(json, BadCommKind);

    /// <summary>
    /// Applies both knobs the BadComm page owns. The bad-comm section is validated by
    /// <see cref="BadCommSettings.TryUpdate"/> — the same gate the page uses — so a malformed rule
    /// set is rejected with its reason rather than half-applied.
    /// </summary>
    public void ImportBadComm(string json)
    {
        BadCommFile file = Parse<BadCommFile>(json, BadCommKind);

        if (file.BadComm is not null && !_badComm.TryUpdate(file.BadComm, out string? error))
        {
            throw new ArgumentException($"The bad-comm settings in the file are invalid: {error}");
        }

        if (file.NetworkDelay is not null)
        {
            _networkDelay.TryUpdate(file.NetworkDelay.LowerMs, file.NetworkDelay.UpperMs);
        }
    }

    // ── Shared ───────────────────────────────────────────────────────────────────────────────────

    private static string Serialize<T>(string kind, string? from, T payload) =>
        JsonSerializer.Serialize(
            new ConfigFile<T> { Kind = kind, ExportedFrom = from, Payload = payload }, Options);

    /// <summary>
    /// Deserializes a file, enforcing that it is the RIGHT kind for the page importing it. A wrong
    /// kind is the likeliest operator mistake (three near-identical downloads), and importing a
    /// network file where batches are expected would replace the wrong data set.
    /// </summary>
    private static T Parse<T>(string json, string expectedKind)
    {
        ConfigFile<T>? file;
        try
        {
            file = JsonSerializer.Deserialize<ConfigFile<T>>(json, Options);
        }
        catch (JsonException ex)
        {
            throw new ArgumentException($"Not a valid configuration file: {ex.Message}");
        }

        if (file is null || file.Payload is null)
        {
            throw new ArgumentException("The file is empty or not a MAYA configuration file.");
        }

        if (!string.Equals(file.Kind, expectedKind, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"This is a '{Label(file.Kind)}' file — import it on that page. This page expects a " +
                $"'{Label(expectedKind)}' file.");
        }

        return file.Payload;
    }

    private static string Label(string? kind) => kind switch
    {
        BatchesKind => "Batch Setup",
        NetworkKind => "Network Setup",
        BadCommKind => "BadComm Setup",
        _ => kind ?? "unknown",
    };

    /// <summary>Names are the cross-deployment identity of a batch, so duplicates are ambiguous.</summary>
    private static void ValidateUniqueBatchNames(BatchStoreSnapshot snapshot)
    {
        string? dupe = snapshot.Batches
            .GroupBy(b => b.Name, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(g => g.Count() > 1)?.Key;
        if (dupe is not null)
        {
            throw new ArgumentException(
                $"The file has more than one batch named '{dupe}'. Batch names must be unique.");
        }
    }

    private static void ValidateUniqueEndpointKeys(NetworkRegistrySnapshot snapshot)
    {
        string? dupe = snapshot.Brokers.Select(b => b.Key)
            .Concat(snapshot.PushTargets.Select(p => p.Key))
            .GroupBy(k => k, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(g => g.Count() > 1)?.Key;
        if (dupe is not null)
        {
            throw new ArgumentException(
                $"The file has more than one network endpoint named '{dupe}'. Names must be unique.");
        }
    }
}

/// <summary>
/// A self-describing config file: what it is, when and where it came from, and the payload. The
/// <see cref="Kind"/> is what stops a file being imported on the wrong page.
/// </summary>
public sealed record ConfigFile<T>
{
    public required string Kind { get; init; }

    public int Version { get; init; } = 1;

    public DateTimeOffset ExportedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Source host, stamped in so an operator can tell three downloads apart.</summary>
    public string? ExportedFrom { get; init; }

    public required T Payload { get; init; }
}

/// <summary>The two field-impairment knobs the BadComm page owns, travelling together.</summary>
public sealed record BadCommFile
{
    public BadCommConfig? BadComm { get; init; }

    public DelayRange? NetworkDelay { get; init; }
}
