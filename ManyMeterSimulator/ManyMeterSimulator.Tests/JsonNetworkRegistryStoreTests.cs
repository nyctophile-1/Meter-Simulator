using ManyMeterSimulator.Networking.Registry;
using Xunit;

namespace ManyMeterSimulator.Tests;

public class JsonNetworkRegistryStoreTests : IDisposable
{
    private readonly string _folder =
        Path.Combine(Path.GetTempPath(), "nicsim-network-tests", Guid.NewGuid().ToString("N"));

    private string FilePath => Path.Combine(_folder, "network.json");

    public void Dispose()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    [Theory]
    [InlineData(DatabaseProvider.SqlServer, "Server=localhost;Database=hes;User ID=test;Password=s3cret")]
    [InlineData(DatabaseProvider.PostgreSql, "Host=localhost;Database=hes;Username=test;Password=s3cret")]
    public void DatabaseConnections_PersistEncrypted_AndSurviveEnvironmentEdits(DatabaseProvider provider, string connectionString)
    {
        var registry = new NetworkRegistry(NewStore());
        registry.SaveDatabase(new DatabaseConnection { Key = "hes-db", Provider = provider, ConnectionString = connectionString }, false);
        registry.AddEnvironment(new HesEnvironment { Key = "hes", BrokerHost = "localhost" }, false);
        Assert.DoesNotContain("s3cret", File.ReadAllText(FilePath));
        var restored = new NetworkRegistry(NewStore());
        var database = Assert.Single(restored.Databases);
        Assert.Equal(provider, database.Provider);
        Assert.Equal(connectionString, database.ConnectionString);
        using var connection = database.CreateConnection();
        Assert.Equal("hes", connection.Database);
        restored.ImportSnapshot(registry.Snapshot());
        Assert.Equal(connectionString, Assert.Single(restored.Databases).ConnectionString);
        restored.DeleteDatabase("hes-db");
        Assert.Empty(new NetworkRegistry(NewStore()).Databases);
        Assert.Single(new NetworkRegistry(NewStore()).Environments);
    }

    [Fact]
    public void InvalidDatabaseImport_DoesNotReplaceExistingEndpoints()
    {
        var registry = new NetworkRegistry(NewStore());
        registry.AddEnvironment(new HesEnvironment { Key = "keep", BrokerHost = "localhost" }, false);
        Assert.Throws<ArgumentException>(() => registry.ImportSnapshot(new NetworkRegistrySnapshot
        {
            Databases = [new DatabaseConnection { Key = "bad", ConnectionString = "invalid" }],
        }));
        Assert.Equal("keep", Assert.Single(registry.Environments).Key);
    }

    private JsonNetworkRegistryStore NewStore(ISecretProtector? protector = null) =>
        new(FilePath, protector ?? new ReversingProtector());

    [Fact]
    public void SaveThenLoad_RoundTripsBothKinds()
    {
        JsonNetworkRegistryStore store = NewStore();

        store.Save(new NetworkRegistrySnapshot
        {
            Brokers = { new BrokerEndpoint { Key = "eqa", Host = "10.0.0.1", Port = 8883, UseTls = true, Username = "meter", Password = "s3cret" } },
            PushTargets = { new PushTargetEndpoint { Key = "hes-1", Address = "fd00::1", Port = 4059 } },
        });

        NetworkRegistrySnapshot loaded = NewStore().Load();

        Assert.Equal("10.0.0.1", loaded.Brokers.Single().Host);
        Assert.Equal(8883, loaded.Brokers.Single().Port);
        Assert.True(loaded.Brokers.Single().UseTls);
        Assert.Equal("s3cret", loaded.Brokers.Single().Password);
        Assert.Equal("fd00::1", loaded.PushTargets.Single().Address);
    }

    [Fact]
    public void Save_WritesThePasswordEncrypted_AndLeavesTheRestReadable()
    {
        NewStore().Save(new NetworkRegistrySnapshot
        {
            Brokers = { new BrokerEndpoint { Key = "eqa", Host = "10.0.0.1", Username = "meter", Password = "s3cret" } },
        });

        string json = File.ReadAllText(FilePath);

        // The one sensitive field must not be on disk in the clear...
        Assert.DoesNotContain("s3cret", json);
        // ...and everything an operator needs to debug must still be.
        Assert.Contains("10.0.0.1", json);
        Assert.Contains("meter", json);
    }

    [Fact]
    public void Save_DoesNotMutateTheCallersLiveObjects()
    {
        var broker = new BrokerEndpoint { Key = "eqa", Host = "10.0.0.1", Password = "s3cret" };

        NewStore().Save(new NetworkRegistrySnapshot { Brokers = { broker } });

        // The in-memory registry keeps plaintext; only the file holds ciphertext.
        Assert.Equal("s3cret", broker.Password);
    }

    /// <summary>
    /// Same policy as the batch store, for the same reason: starting empty would leave every batch
    /// bound to a key that no longer resolves — meters that answer nothing, with no error anywhere.
    /// </summary>
    [Fact]
    public void Load_CorruptFile_ThrowsRatherThanStartingEmpty()
    {
        Directory.CreateDirectory(_folder);
        File.WriteAllText(FilePath, "{ this is not json");

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => NewStore().Load());
        Assert.Contains("could not be parsed", ex.Message);
    }

    [Fact]
    public void Load_MissingFile_StartsEmpty()
    {
        NetworkRegistrySnapshot loaded = NewStore().Load();

        Assert.Empty(loaded.Brokers);
        Assert.Empty(loaded.PushTargets);
    }

    [Fact]
    public void Load_UndecryptablePassword_YieldsEmptyWithoutTakingTheRegistryDown()
    {
        NewStore().Save(new NetworkRegistrySnapshot
        {
            Brokers = { new BrokerEndpoint { Key = "eqa", Host = "10.0.0.1", Password = "s3cret" } },
        });

        // Stand-in for a lost or replaced key ring.
        NetworkRegistrySnapshot loaded = NewStore(new FailingProtector()).Load();

        Assert.Equal(string.Empty, loaded.Brokers.Single().Password);
        Assert.Equal("10.0.0.1", loaded.Brokers.Single().Host);
    }

    /// <summary>Encryption stand-in: reversible without needing a real key ring in a unit test.</summary>
    private sealed class ReversingProtector : ISecretProtector
    {
        public string Protect(string plaintext) => new(plaintext.Reverse().ToArray());

        public string Unprotect(string ciphertext) => new(ciphertext.Reverse().ToArray());
    }

    private sealed class FailingProtector : ISecretProtector
    {
        public string Protect(string plaintext) => plaintext;

        public string Unprotect(string ciphertext) => string.Empty;
    }
}
