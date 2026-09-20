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
    [InlineData(0, "gate_17_1", "sink1", 1u)]
    [InlineData(3, "gate_17_1", "sink0", 0u)]
    [InlineData(499, "gate_17_1", "sink0", 0u)]
    [InlineData(500, "gate_17_1", "sink1", 1u)]
    [InlineData(999, "gate_17_1", "sink0", 0u)]
    [InlineData(1000, "gate_17_2", "sink1", 1u)]
    public void GatewaysUseBatchRelativeGroupsAndFourSinks(int offset, string gateway, string wirepasSink, uint kmeshSink)
    {
        Assert.Equal((gateway, wirepasSink), BatchGatewayAssignment.For(17, 2300002, 2300002 + offset));
        Assert.Equal((gateway, kmeshSink), BatchGatewayAssignment.ForKmesh(17, 2300002, 2300002 + offset));
    }

    [Fact]
    public void EditsValidateAndFreezeConfirmedValues()
    {
        var definition = new HesRegistrationDefinition(1, 1, 7, "model", "Kimbal", "MY01.1", "6", "D1", "", 2025,
            1, 1, 15, "fd00::/64", 4059, "TCP", "direct_tcp", "direct_tcp", -1, "demo", "demo", "demo");
        var draft = HesRegistrationEdits.From(definition);
        draft.Category = "D3"; draft.CtRatio = 100; draft.PtRatio = 10; draft.CapturePeriodMinutes = 60;
        var confirmed = draft.Apply(definition);
        draft.CtRatio = 999;
        Assert.Equal(100, confirmed.CtRatio);
        Assert.Equal("D3", confirmed.Category);
        Assert.Equal(60, confirmed.CapturePeriod);
        Assert.Equal("D1", definition.Category);
        draft.CapturePeriodMinutes = 900;
        Assert.Throws<InvalidOperationException>(() => draft.Apply(definition));
        draft.CapturePeriodMinutes = 15; draft.Category = "D9";
        Assert.Throws<InvalidOperationException>(() => draft.Apply(definition));
        draft.Category = "D2"; draft.PtRatio = 0;
        Assert.Throws<InvalidOperationException>(() => draft.Apply(definition));
    }
    [Theory]
    [InlineData(NicType.Tcp4G, "direct_tcp", "direct_tcp", -1)]
    [InlineData(NicType.Mqtt4G, "direct_4g", "direct_4g", -1)]
    [InlineData(NicType.Mqtt4GImg, "direct_4g", "direct_4g", -1)]
    [InlineData(NicType.MqttWirepas, "gate_1_1", "sink0", 3)]
    [InlineData(NicType.MqttKmesh, "gate_1_1", "0", -1)]
    public void DefinitionUsesActualModelAndTransport(NicType nic, string gateway, string sink, int endpoint)
    {
        var templates = new TemplateRegistry(Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
            new TestEnvironment(), NullLogger<TemplateRegistry>.Instance);
        var factory = new HesRegistrationDefinitionFactory(templates, Options.Create(new BrainOptions()), Options.Create(new TcpOptions()));
        var batch = new MeterRegistry().AddBatch("test", "D1_Master.xml", 10, nic, hesTemplateId: 7);
        var d = factory.Create(batch, 7);
        Assert.Equal("D1", d.Category);
        Assert.Equal("6", d.MeterType);
        Assert.Equal(15, d.CapturePeriod);
        Assert.Equal("Kimbal", d.Manufacturer);
        Assert.Equal("MY01.1", d.Firmware);
        Assert.True(d.CtRatio > 0);
        Assert.True(d.PtRatio > 0);
        Assert.Equal(nic switch { NicType.Tcp4G => "TCP", NicType.MqttWirepas => "RF", NicType.MqttKmesh => "KMesh", _ => "MQTT4G" }, d.Module);
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
        "Kimbal", "MY01.1", "6", "D1", "(10-60) A", 2025, 1, 1, 15,
        "fd00:6d65:7472::/64", 4059, "TCP", "direct_tcp", "direct_tcp", -1,
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
                nodeid citext, metertemplateid bigint, ip citext, port int CHECK(port > 0), communicationmodule citext, blockcaptureperiod int,
                installedon timestamp, originalinstalledon timestamp);
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
    public async Task EditedPreviewSubmitsExactValuesAndBatchRelativeRouting()
    {
        await Reset();
        var folder = Path.Combine(Path.GetTempPath(), "maya-registration-edits-" + Guid.NewGuid());
        var meters = new MeterRegistry();
        meters.AddBatch("other", "D1_Master.xml", 2300001);
        var batch = meters.AddBatch("edited", "D1_Master.xml", 1001, NicType.MqttWirepas, hesTemplateId: 7);
        var network = new NetworkRegistry();
        network.SaveDatabase(Database(), false);
        var host = new TestEnvironment();
        var templates = new TemplateRegistry(Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }), host, NullLogger<TemplateRegistry>.Instance);
        var factory = new HesRegistrationDefinitionFactory(templates, Options.Create(new BrainOptions()), Options.Create(new TcpOptions()));
        var service = new HesBatchRegistrationService(meters, network, factory, _store, new ManyMeterSimulator.Diagnostics.SessionRegistry(meters),
            Options.Create(new PersistenceOptions { Folder = folder }), host, NullLogger<HesBatchRegistrationService>.Instance);
        var admin = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "Admin"), new Claim(ClaimTypes.Role, "Admin")], "test"));
        try
        {
            var preview = await service.PreviewAsync(admin, batch.Id, Database().Key, 7, default);
            var draft = preview.EditableValues;
            draft.Category = "D3"; draft.CtRatio = 100; draft.PtRatio = 10; draft.CapturePeriodMinutes = 30;
            var confirmed = service.RevisePreview(admin, preview, draft);
            draft.CtRatio = 999;
            var receipt = await service.ReplaceAsync(admin, confirmed, false, default);
            Assert.Equal(1001, receipt.Count);
            Assert.Equal(1001L, await Sql("""
                SELECT count(*) FROM kimbaldb_dbo.nameplate WHERE metercategory='D3' AND ctratio=100 AND ptratio=10
                AND blockcaptureperiod=30 AND manufacturer='Kimbal' AND firmwareversion='MY01.1'
                AND communicationmodule='RF' AND deviceid=nodeid::text || 'MAYA'
                AND installedon=originalinstalledon AND abs(extract(epoch FROM (installedon-(now() at time zone 'UTC')))) < 30
                """));
            Assert.Equal("gate_2_1/sink0", await Sql("SELECT gatewayid::text || '/' || sinkid::text FROM kimbaldb_dbo.latestrouting WHERE nodeid='1002300501'"));
            Assert.Equal("gate_2_1/sink1", await Sql("SELECT gatewayid::text || '/' || sinkid::text FROM kimbaldb_dbo.latestrouting WHERE nodeid='1002300502'"));
            Assert.Equal("gate_2_2/sink1", await Sql("SELECT gatewayid::text || '/' || sinkid::text FROM kimbaldb_dbo.latestrouting WHERE nodeid='1002301002'"));
            Assert.Equal(1000L, await Sql("SELECT count(*) FROM kimbaldb_dbo.latestrouting WHERE gatewayid='gate_2_1'"));
            Assert.Equal(1L, await Sql("SELECT count(*) FROM kimbaldb_dbo.latestrouting WHERE gatewayid='gate_2_2'"));
            Assert.Equal(0L, await Sql("SELECT count(*) FROM kimbaldb_dbo.latestrouting WHERE gatewayid='gate_2_3'"));
            await Assert.ThrowsAsync<InvalidOperationException>(() => service.ReplaceAsync(admin, confirmed, false, default));
        }
        finally { if (Directory.Exists(folder)) Directory.Delete(folder, true); }
    }

    [LocalRegistrationPostgresFact]
    public async Task KmeshRegistrationUsesNumericSinksAndGeneratedGateways()
    {
        await Reset();
        await Provision(Definition(1234, 501) with { Module = "KMesh", GroupGateways = true, BatchId = 4 });
        Assert.Equal("gate_4_1/3", await Sql("SELECT gatewayid::text || '/' || sinkid::text FROM kimbaldb_dbo.latestrouting WHERE nodeid='1000001733'"));
        Assert.Equal("gate_4_2/0", await Sql("SELECT gatewayid::text || '/' || sinkid::text FROM kimbaldb_dbo.latestrouting WHERE nodeid='1000001734'"));
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
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
