using System.Security.Claims;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using Xunit;

namespace ManyMeterSimulator.Tests;

public sealed class HesRegistrationLeaseTests
{
    [Theory]
    [InlineData(NicType.Tcp4G, "direct_tcp", "direct_tcp", -1)]
    [InlineData(NicType.Mqtt4G, "direct_4g", "direct_4g", -1)]
    [InlineData(NicType.Mqtt4GImg, "direct_4g", "direct_4g", -1)]
    [InlineData(NicType.MqttWirepas, "wirepas-gateway", "sink1", 3)]
    [InlineData(NicType.MqttKmesh, "kmesh-gateway", "1", -1)]
    public void DefinitionUsesActualModelAndTransport(NicType nic, string gateway, string sink, int endpoint)
    {
        var templates = new TemplateRegistry(Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
            new TestEnvironment(), NullLogger<TemplateRegistry>.Instance);
        var factory = new HesRegistrationDefinitionFactory(templates, Options.Create(new BrainOptions()), Options.Create(new TcpOptions()),
            Options.Create(new CustomPushOptions { WirepasGatewayId = "wirepas-gateway" }), Options.Create(new PushOptions { KmeshGatewayId = "kmesh-gateway" }));
        var batch = new MeterRegistry().AddBatch("test", "D1_Master.xml", 10, nic, hesTemplateId: 7);
        var d = factory.Create(batch, 7);
        Assert.Equal("D1", d.Category);
        Assert.Equal("6", d.MeterType);
        Assert.Equal(900, d.CapturePeriod);
        Assert.Equal(gateway, d.Gateway);
        Assert.Equal(sink, d.Sink);
        Assert.Equal(endpoint, d.Endpoint);
        Assert.Equal(64, d.ModelHash.Length);
        Assert.Equal(64, d.Fingerprint.Length);
        Assert.Throws<InvalidOperationException>(() => factory.Create(batch, 8));
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
    [Fact]
    public void RegistrationLeaseProtectsStoppedBatchAndReleasesIt()
    {
        var registry = new MeterRegistry();
        var batch = registry.AddBatch("test", "test.xml", 10);
        using (registry.AcquireRegistrationLease(batch))
        {
            Assert.False(registry.TryStart(batch.Id));
            Assert.False(registry.TryMarkStarting(batch));
            Assert.False(registry.Delete(batch.Id));
            Assert.False(registry.SetNetworkBinding(batch.Id, "other"));
            Assert.Throws<InvalidOperationException>(registry.Reset);
            Assert.Throws<InvalidOperationException>(() => registry.ImportSnapshot(registry.Snapshot()));
            Assert.Throws<InvalidOperationException>(() => registry.AcquirePushLease([batch.Id]));
            Assert.False(registry.TryAdmitSession(batch.StartIndex, () => throw new Exception("Must not admit while provisioning")));
        }
        Assert.True(registry.TryStart(batch.Id));
        Assert.Throws<InvalidOperationException>(() => registry.AcquireRegistrationLease(batch));
    }

    [Fact]
    public void ExistingPushRunBlocksRegistrationUntilDisposed()
    {
        var registry = new MeterRegistry();
        var batch = registry.AddBatch("test", "test.xml", 10);
        var push = registry.AcquirePushLease([batch.Id]);
        Assert.Throws<InvalidOperationException>(() => registry.AcquireRegistrationLease(batch));
        push.Dispose(); push.Dispose();
        using var registration = registry.AcquireRegistrationLease(batch);
    }

    [Fact]
    public async Task ServiceRejectsUnauthenticatedAndNonAdminBeforeAccessingDatabase()
    {
        var service = new HesBatchRegistrationService(null!, null!, null!, null!, null!, null!, null!, null!);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => service.PreviewAsync(new ClaimsPrincipal(), 1, "db", 7, default));
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "viewer")], "test"));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => service.PreviewAsync(user, 1, "db", 7, default));
    }
}

public sealed class LocalRegistrationPostgresFactAttribute : FactAttribute
{
    public LocalRegistrationPostgresFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("MAYA_REGISTRATION_LOCAL_TEST_CONNECTION")))
            Skip = "Requires a disposable localhost database named maya_registration_test. See docs/hes-batch-registration.md.";
    }
}

[CollectionDefinition("Registration PostgreSQL", DisableParallelization = true)]
public sealed class RegistrationPostgresCollection { }

[Collection("Registration PostgreSQL")]
public sealed class HesRegistrationPostgresTests
{
    private readonly HesRegistrationDatabase _store = new();
    private static DatabaseConnection Database()
    {
        var builder = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("MAYA_REGISTRATION_LOCAL_TEST_CONNECTION"));
        if (builder.Host != "127.0.0.1" || builder.Database != "maya_registration_test" || builder.Username != "maya_test")
            throw new InvalidOperationException("Tests may only mutate the disposable local maya_test database.");
        return new() { Key = "local fixture", Provider = DatabaseProvider.PostgreSql, ConnectionString = builder.ConnectionString };
    }
    private static HesRegistrationDefinition Definition(long start = 1, long count = 2) => new(start, count, 7, "fixture-model",
        "MAYA", "test", "6", "D1", "(10-60) A", 2025, null, null, 900,
        "fd00:6d65:7472::/64", 4059, "4G", "direct_tcp", "direct_tcp", -1,
        "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAA", "12345678");

    private static async Task Reset()
    {
        await Sql("""
            DROP SCHEMA IF EXISTS kimbaldb_dbo CASCADE;
            CREATE SCHEMA kimbaldb_dbo;
            CREATE EXTENSION IF NOT EXISTS citext;
            CREATE TABLE kimbaldb_dbo.metertemplate(id bigint PRIMARY KEY);
            INSERT INTO kimbaldb_dbo.metertemplate VALUES(7);
            CREATE TABLE kimbaldb_dbo.nameplate(
                id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, guid uuid NOT NULL, meterno citext UNIQUE,
                deviceid citext, manufacturer citext, firmwareversion citext, metertype citext, metercategory citext,
                rating citext, yearofmanufacture int, ctratio int, ptratio int, createddate timestamp NOT NULL,
                nodeid citext, metertemplateid bigint, ip citext, port int CHECK(port > 0), communicationmodule citext, blockcaptureperiod int);
            CREATE TABLE kimbaldb_dbo.metersecurity(
                id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, meterno citext NOT NULL, masterkey citext NOT NULL,
                globalkey citext NOT NULL, hlsussecret citext NOT NULL, hlsfwsecret citext NOT NULL, llsmrsecret citext NOT NULL, createddate timestamp NOT NULL);
            CREATE TABLE kimbaldb_dbo.latestrouting(
                id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, createddate timestamp NOT NULL, nodeid citext NOT NULL,
                gatewayid citext NOT NULL, sinkid citext NOT NULL, linkscore bigint NOT NULL, lastcommunicatedon timestamp NOT NULL,
                sourceendpoint bigint, hopcount int, iscommunicating bool DEFAULT false);
            CREATE TABLE kimbaldb_dbo.history(value text);
            INSERT INTO kimbaldb_dbo.history VALUES ('preserve');
            """);
    }
    private static async Task<object?> Sql(string sql)
    {
        await using var connection = new NpgsqlConnection(Database().ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        return await command.ExecuteScalarAsync();
    }
    private async Task Provision(HesRegistrationDefinition d)
    {
        var preview = await _store.PreviewAsync(Database(), d, default);
        await _store.ReplaceAsync(Database(), d, preview, false, default);
    }

    [LocalRegistrationPostgresFact]
    public async Task ChunkedReplacementIsIdempotentAndPreservesNeighboursAndHistory()
    {
        await Reset();
        await Provision(Definition(1002, 1));
        var outsideId = await Sql("SELECT id FROM kimbaldb_dbo.nameplate WHERE nodeid='1000001002'");
        var d = Definition(1, 1001);
        await Provision(d);
        // Duplicate security/routing belonging to the approved set are removed on replacement.
        await Sql("INSERT INTO kimbaldb_dbo.latestrouting(createddate,nodeid,gatewayid,sinkid,linkscore,lastcommunicatedon) VALUES(now(),'1000000001','old','old',0,now())");
        await Provision(d);
        var result = await _store.PreviewAsync(Database(), d, default);
        Assert.Equal(new RegistrationCounts(1001, 1001, 1001), result.Existing);
        Assert.Equal(0, result.Conflicts);
        Assert.Equal(0, result.LegacyMeters);
        Assert.Equal(outsideId, await Sql("SELECT id FROM kimbaldb_dbo.nameplate WHERE nodeid='1000001002'"));
        Assert.Equal("preserve", await Sql("SELECT value FROM kimbaldb_dbo.history"));
        Assert.Equal(0L, await Sql("SELECT count(*) FROM kimbaldb_dbo.latestrouting WHERE iscommunicating"));
        Assert.DoesNotContain(d.GlobalKey, result.ToString());
        Assert.DoesNotContain(d.GlobalKey, d.ToString());
    }

    [LocalRegistrationPostgresFact]
    public async Task OutOfRangeSerialCollisionAndOrphanSecurityBlockReplacement()
    {
        await Reset();
        await Provision(Definition());
        await Sql("UPDATE kimbaldb_dbo.nameplate SET nodeid='9000000000' WHERE meterno='MY00000001'");
        var preview = await _store.PreviewAsync(Database(), Definition(), default);
        Assert.True(preview.Conflicts > 0);
        await Assert.ThrowsAsync<InvalidOperationException>(() => _store.ReplaceAsync(Database(), Definition(), preview, true, default));
        Assert.Equal("9000000000", await Sql("SELECT nodeid::text FROM kimbaldb_dbo.nameplate WHERE meterno='MY00000001'"));
        await Sql("DELETE FROM kimbaldb_dbo.nameplate WHERE meterno='MY00000001'");
        Assert.True((await _store.PreviewAsync(Database(), Definition(), default)).Conflicts > 0);
    }

    [LocalRegistrationPostgresFact]
    public async Task LegacyAdoptionRequiresMatchingDeviceAndExplicitAcknowledgment()
    {
        await Reset();
        await Provision(Definition());
        await Sql("UPDATE kimbaldb_dbo.nameplate SET guid='11111111-1111-1111-1111-111111111111'");
        var preview = await _store.PreviewAsync(Database(), Definition(), default);
        Assert.Equal(2, preview.LegacyMeters);
        await Assert.ThrowsAsync<InvalidOperationException>(() => _store.ReplaceAsync(Database(), Definition(), preview, false, default));
        await _store.ReplaceAsync(Database(), Definition(), preview, true, default);
        Assert.Equal(0, (await _store.PreviewAsync(Database(), Definition(), default)).LegacyMeters);
        await Sql("UPDATE kimbaldb_dbo.nameplate SET guid='11111111-1111-1111-1111-111111111111', deviceid='unrelated'");
        Assert.True((await _store.PreviewAsync(Database(), Definition(), default)).Conflicts > 0);
    }

    [LocalRegistrationPostgresFact]
    public async Task InsertFailureAfterDeleteRollsBackAllThreeTables()
    {
        await Reset();
        await Provision(Definition());
        var before = await _store.PreviewAsync(Database(), Definition(), default);
        var invalid = Definition() with { Port = -1 };
        await Assert.ThrowsAsync<PostgresException>(() => _store.ReplaceAsync(Database(), invalid, before, false, default));
        var after = await _store.PreviewAsync(Database(), Definition(), default);
        Assert.Equal(before.Fingerprint, after.Fingerprint);
        Assert.Equal(before.Existing, after.Existing);
    }

    [LocalRegistrationPostgresFact]
    public async Task ConcurrentReplacementRejectsStalePreviewAndCancelledRequestPreservesRows()
    {
        await Reset();
        await Provision(Definition());
        var before = await _store.PreviewAsync(Database(), Definition(), default);
        var results = await Task.WhenAll(Enumerable.Range(0, 2).Select(async _ =>
        {
            try { await _store.ReplaceAsync(Database(), Definition(), before, false, default); return true; }
            catch (InvalidOperationException) { return false; }
        }));
        Assert.Single(results, r => r);
        var fresh = await _store.PreviewAsync(Database(), Definition(), default);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _store.ReplaceAsync(Database(), Definition(), fresh, false, new CancellationToken(true)));
        Assert.Equal(fresh.Fingerprint, (await _store.PreviewAsync(Database(), Definition(), default)).Fingerprint);
    }

    [LocalRegistrationPostgresFact]
    public async Task ReadOnlyTargetAndMissingTemplateAreRejected()
    {
        await Reset();
        var builder = new NpgsqlConnectionStringBuilder(Database().ConnectionString) { Options = "-c default_transaction_read_only=on" };
        var readOnly = Database() with { ConnectionString = builder.ConnectionString };
        await Assert.ThrowsAsync<InvalidOperationException>(() => _store.PreviewAsync(readOnly, Definition(), default));
        await Assert.ThrowsAsync<InvalidOperationException>(() => _store.PreviewAsync(Database(), Definition() with { TemplateId = 999 }, default));
    }
}
