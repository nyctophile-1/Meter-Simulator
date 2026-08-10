using System.Text.Json;
using System.Text.Json.Serialization;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Networking.Registry;

/// <summary>
/// File-backed <see cref="INetworkRegistryStore"/>: one human-readable JSON document at
/// <c>data/network.json</c>, written atomically (temp file + rename) so a crash mid-save can never
/// leave a half-written, unparseable store.
///
/// <para>
/// Broker passwords are encrypted on the way out and decrypted on the way in, so the in-memory
/// registry only ever holds plaintext and the file only ever holds ciphertext. Every other field
/// stays readable on purpose — a config file an operator cannot read is a file they cannot debug.
/// </para>
/// </summary>
public sealed class JsonNetworkRegistryStore : INetworkRegistryStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _filePath;
    private readonly ISecretProtector _protector;
    private readonly ILogger<JsonNetworkRegistryStore>? _logger;
    private readonly object _fileLock = new();

    public JsonNetworkRegistryStore(
        IOptions<PersistenceOptions> options,
        IHostEnvironment env,
        ISecretProtector protector,
        ILogger<JsonNetworkRegistryStore> logger)
        : this(ResolvePath(options.Value, env), protector, logger)
    {
    }

    /// <summary>Test/opt-in seam: point the store at an explicit absolute file path.</summary>
    public JsonNetworkRegistryStore(
        string filePath, ISecretProtector protector, ILogger<JsonNetworkRegistryStore>? logger = null)
    {
        _filePath = filePath;
        _protector = protector;
        _logger = logger;
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
        _logger?.LogInformation("Network registry file: {Path}", _filePath);
    }

    public NetworkRegistrySnapshot Load()
    {
        lock (_fileLock)
        {
            if (!File.Exists(_filePath))
            {
                _logger?.LogInformation(
                    "No network registry at {Path} yet; starting with an empty registry.", _filePath);
                return new NetworkRegistrySnapshot();
            }

            string json = File.ReadAllText(_filePath);
            if (string.IsNullOrWhiteSpace(json))
            {
                return new NetworkRegistrySnapshot();
            }

            NetworkRegistrySnapshot snapshot;
            try
            {
                snapshot = JsonSerializer.Deserialize<NetworkRegistrySnapshot>(json, SerializerOptions)
                           ?? new NetworkRegistrySnapshot();
            }
            catch (JsonException ex)
            {
                // Same policy as the batch store, for the same reason: starting empty would leave
                // every batch bound to a key that no longer resolves — meters that answer nothing,
                // with no error to point at. The operator must fix or remove the file.
                throw new InvalidOperationException(
                    $"Network registry '{_filePath}' is present but could not be parsed. Refusing to " +
                    "start with an empty registry (every batch's broker and push binding would " +
                    "silently stop resolving). Fix or remove the file.", ex);
            }

            foreach (HesEnvironment env in snapshot.Environments)
            {
                env.BrokerPassword = _protector.Unprotect(env.BrokerPassword);
            }

            foreach (BrokerEndpoint broker in snapshot.Brokers)
            {
                broker.Password = _protector.Unprotect(broker.Password);
            }

            return snapshot;
        }
    }

    public void Save(NetworkRegistrySnapshot snapshot)
    {
        lock (_fileLock)
        {
            var onDisk = snapshot with
            {
                Environments = snapshot.Environments.Select(EncryptedEnv).ToList(),
                Brokers = snapshot.Brokers.Select(Encrypted).ToList(),
            };

            string json = JsonSerializer.Serialize(onDisk, SerializerOptions);
            string tempPath = _filePath + ".tmp";

            File.WriteAllText(tempPath, json);
            File.Move(tempPath, _filePath, overwrite: true);
        }
    }

    private HesEnvironment EncryptedEnv(HesEnvironment env) => new()
    {
        Key = env.Key,
        Name = env.Name,
        TcpHost = env.TcpHost,
        TcpPort = env.TcpPort,
        BrokerHost = env.BrokerHost,
        BrokerPort = env.BrokerPort,
        BrokerUsername = env.BrokerUsername,
        BrokerPassword = _protector.Protect(env.BrokerPassword),
        BrokerUseTls = env.BrokerUseTls,
        Enabled = env.Enabled,
        Verified = env.Verified,
        LastVerifiedUtc = env.LastVerifiedUtc,
        CreatedAtUtc = env.CreatedAtUtc,
    };

    private BrokerEndpoint Encrypted(BrokerEndpoint broker) => new()
    {
        Key = broker.Key,
        Host = broker.Host,
        Port = broker.Port,
        Username = broker.Username,
        Password = _protector.Protect(broker.Password),
        UseTls = broker.UseTls,
        Enabled = broker.Enabled,
        Verified = broker.Verified,
        LastVerifiedUtc = broker.LastVerifiedUtc,
        CreatedAtUtc = broker.CreatedAtUtc,
    };

    private static string ResolvePath(PersistenceOptions options, IHostEnvironment env)
    {
        string folder = Path.IsPathRooted(options.Folder)
            ? options.Folder
            : Path.Combine(env.ContentRootPath, options.Folder);
        return Path.GetFullPath(Path.Combine(folder, options.NetworkRegistryFileName));
    }
}
