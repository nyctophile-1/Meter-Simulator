using System.Data;
using System.Security.Cryptography;
using System.Text;
using ManyMeterSimulator.Networking.Registry;
using Npgsql;
using NpgsqlTypes;

namespace ManyMeterSimulator.Provisioning;

public sealed record RegistrationCounts(long Nameplates, long Security, long Routes);
public sealed record RegistrationInspection(string Target, RegistrationCounts Existing, long LegacyMeters,
    long Conflicts, IReadOnlyList<string> Issues, string Fingerprint);
public sealed class RegistrationCommitUncertainException() : Exception(
    "The connection was lost while committing. The database outcome is unknown. Preview again and verify the registration before retrying.");

public sealed class HesRegistrationDatabase
{
    private const int ChunkSize = 1000;

    public async Task<RegistrationInspection> PreviewAsync(DatabaseConnection database, HesRegistrationDefinition definition, CancellationToken ct)
    {
        await using var connection = OpenConnection(database);
        await connection.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await Execute(connection, "SET TRANSACTION READ ONLY", ct);
        await Configure(connection, ct);
        var inspection = await Inspect(connection, definition, ct);
        await transaction.RollbackAsync(ct);
        return inspection;
    }

    public async Task ReplaceAsync(DatabaseConnection database, HesRegistrationDefinition definition,
        RegistrationInspection preview, bool adoptLegacy, CancellationToken ct)
    {
        await using var connection = OpenConnection(database);
        await connection.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await Configure(connection, ct);
        // These HES tables have no uniqueness on NodeId. Lock all three for atomic revalidation
        // against both other MAYA hosts and HES writers, with a short lock timeout.
        await Execute(connection, "LOCK TABLE kimbaldb_dbo.nameplate, kimbaldb_dbo.metersecurity, kimbaldb_dbo.latestrouting IN SHARE ROW EXCLUSIVE MODE", ct);
        var current = await Inspect(connection, definition, ct);
        if (current.Target != preview.Target || current.Fingerprint != preview.Fingerprint)
            throw new InvalidOperationException("Registration changed after preview. Preview again before replacing it.");
        if (current.Conflicts != 0 || current.LegacyMeters > 0 && !adoptLegacy)
            throw new InvalidOperationException("Resolve ownership conflicts or explicitly adopt the matching legacy MAYA registrations first.");

        var now = DateTime.SpecifyKind(DateTime.UtcNow, DateTimeKind.Unspecified);
        foreach (var indices in Chunks(definition))
        {
            ct.ThrowIfCancellationRequested();
            var nodes = indices.Select(MeterNodeIds.Format).ToArray();
            var serials = indices.Select(MeterRegistry.FormatSerial).ToArray();
            await using var delete = new NpgsqlCommand("""
                DELETE FROM kimbaldb_dbo.metersecurity WHERE meterno = ANY(@serials::citext[]);
                DELETE FROM kimbaldb_dbo.latestrouting WHERE nodeid = ANY(@nodes::citext[]);
                DELETE FROM kimbaldb_dbo.nameplate WHERE nodeid = ANY(@nodes::citext[]);
                """, connection);
            AddIdentities(delete, nodes, serials);
            await delete.ExecuteNonQueryAsync(ct);
            await Insert(connection, definition, indices, now, ct);
        }
        // Inspect again while the same locks are held: exactly one owned registration per meter.
        var result = await Inspect(connection, definition, ct);
        if (result.Conflicts != 0 || result.LegacyMeters != 0 || result.Existing != new RegistrationCounts(definition.Count, definition.Count, definition.Count))
            throw new InvalidOperationException("Registration verification failed; replacement was rolled back.");
        ct.ThrowIfCancellationRequested();
        try { await transaction.CommitAsync(CancellationToken.None); }
        catch (PostgresException) { throw; }
        catch (Exception) { throw new RegistrationCommitUncertainException(); }
    }

    private static NpgsqlConnection OpenConnection(DatabaseConnection database)
    {
        if (database.Provider != DatabaseProvider.PostgreSql)
            throw new InvalidOperationException("HES batch provisioning requires a PostgreSQL connection.");
        var builder = new NpgsqlConnectionStringBuilder(database.ConnectionString)
        {
            Timeout = 10, CommandTimeout = 60, Pooling = false, IncludeErrorDetail = false,
            ApplicationName = "MAYA batch registration"
        };
        return new(builder.ConnectionString);
    }

    private static async Task Configure(NpgsqlConnection connection, CancellationToken ct) =>
        await Execute(connection, "SET LOCAL lock_timeout = '5s'; SET LOCAL statement_timeout = '60s'; SET LOCAL search_path = kimbaldb_dbo, public", ct);

    private static async Task<RegistrationInspection> Inspect(NpgsqlConnection connection, HesRegistrationDefinition d, CancellationToken ct)
    {
        if (d.StartIndex < 1 || d.Count < 1 || d.EndIndex > MeterRegistry.MaxIndex) throw new InvalidOperationException("Invalid batch range.");
        string target;
        await using (var command = new NpgsqlCommand("""
            SELECT current_database(), coalesce(inet_server_addr()::text, 'local'), inet_server_port(),
                   pg_is_in_recovery(), current_setting('default_transaction_read_only');
            """, connection))
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            await reader.ReadAsync(ct);
            if (reader.GetBoolean(3) || reader.GetString(4) == "on")
                throw new InvalidOperationException("Select a writable PostgreSQL primary, not a replica or read-only connection.");
            target = $"{reader.GetString(0)} @ {reader.GetString(1)}:{reader.GetInt32(2)}";
        }
        await using (var command = new NpgsqlCommand("""
            SELECT EXISTS(SELECT 1 FROM kimbaldb_dbo.metertemplate WHERE id = @template),
              EXISTS(SELECT 1 FROM pg_constraint WHERE contype = 'f' AND
                (conrelid = ANY(ARRAY['kimbaldb_dbo.nameplate'::regclass, 'kimbaldb_dbo.metersecurity'::regclass, 'kimbaldb_dbo.latestrouting'::regclass])
                OR confrelid = ANY(ARRAY['kimbaldb_dbo.nameplate'::regclass, 'kimbaldb_dbo.metersecurity'::regclass, 'kimbaldb_dbo.latestrouting'::regclass]))),
              EXISTS(SELECT 1 FROM pg_trigger WHERE NOT tgisinternal AND
                tgrelid = ANY(ARRAY['kimbaldb_dbo.nameplate'::regclass, 'kimbaldb_dbo.metersecurity'::regclass, 'kimbaldb_dbo.latestrouting'::regclass]));
            """, connection))
        {
            command.Parameters.AddWithValue("template", d.TemplateId);
            await using var reader = await command.ExecuteReaderAsync(ct);
            await reader.ReadAsync(ct);
            if (!reader.GetBoolean(0)) throw new InvalidOperationException("The selected HES template ID does not exist in this database.");
            if (reader.GetBoolean(1) || reader.GetBoolean(2))
                throw new InvalidOperationException("This target has registration foreign keys or triggers requiring a reviewed replacement strategy.");
        }
        long plates = 0, security = 0, routes = 0, legacy = 0, conflicts = 0;
        var issues = new List<string>();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Issue(string text) { conflicts++; if (issues.Count < 10) issues.Add(text); }
        void Hash(string table, NpgsqlDataReader reader)
        {
            // Row version + ID detects every committed update without reading security material.
            hash.AppendData(Encoding.UTF8.GetBytes($"{table}:{reader.GetInt64(0)}:{reader.GetString(1)}\n"));
        }
        foreach (var indices in Chunks(d))
        {
            var nodes = indices.Select(MeterNodeIds.Format).ToArray();
            var serials = indices.Select(MeterRegistry.FormatSerial).ToArray();
            var expected = indices.ToDictionary(MeterNodeIds.Format);
            var owned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            await using (var command = new NpgsqlCommand("""
                SELECT id, xmin::text, nodeid::text, meterno::text, guid, deviceid::text
                FROM kimbaldb_dbo.nameplate WHERE nodeid = ANY(@nodes::citext[]) OR meterno = ANY(@serials::citext[]) ORDER BY id
                """, connection))
            {
                AddIdentities(command, nodes, serials);
                await using var reader = await command.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    plates++; Hash("n", reader);
                    string node = reader.IsDBNull(2) ? "" : reader.GetString(2);
                    string serial = reader.IsDBNull(3) ? "" : reader.GetString(3);
                    if (!expected.TryGetValue(node, out var index) || !string.Equals(serial, MeterRegistry.FormatSerial(index), StringComparison.OrdinalIgnoreCase))
                    { Issue($"Node/serial collision involving {node}. No records will be replaced."); continue; }
                    if (!owned.Add(node)) { Issue($"Multiple nameplates use node {node}."); continue; }
                    if (reader.GetGuid(4) != HesRegistrationDefinition.OwnershipId(index))
                    {
                        if (reader.IsDBNull(5) || !(string.Equals(reader.GetString(5), "CRY" + serial, StringComparison.OrdinalIgnoreCase)
                            || string.Equals(reader.GetString(5), HesRegistrationDefinition.DeviceId(index), StringComparison.OrdinalIgnoreCase)))
                            Issue($"MAYA ownership cannot be established for node {node}.");
                        else legacy++;
                    }
                }
            }
            await using (var command = new NpgsqlCommand("""
                SELECT id, xmin::text, meterno::text FROM kimbaldb_dbo.metersecurity WHERE meterno = ANY(@serials::citext[]) ORDER BY id;
                SELECT id, xmin::text, nodeid::text FROM kimbaldb_dbo.latestrouting WHERE nodeid = ANY(@nodes::citext[]) ORDER BY id;
                """, connection))
            {
                AddIdentities(command, nodes, serials);
                var ownedSerials = owned.Select(n => MeterRegistry.FormatSerial(expected[n])).ToHashSet(StringComparer.OrdinalIgnoreCase);
                await using var reader = await command.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    security++; Hash("s", reader);
                    if (!ownedSerials.Contains(reader.GetString(2))) Issue("Security exists without a verified in-range nameplate; orphan cleanup is blocked.");
                }
                await reader.NextResultAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    routes++; Hash("r", reader);
                    if (!owned.Contains(reader.GetString(2))) Issue("Routing exists without a verified in-range nameplate; orphan cleanup is blocked.");
                }
            }
        }
        return new(target, new(plates, security, routes), legacy, conflicts, issues, Convert.ToHexString(hash.GetHashAndReset()));
    }

    private static async Task Insert(NpgsqlConnection connection, HesRegistrationDefinition d, long[] indices, DateTime now, CancellationToken ct)
    {
        await using (var copy = await connection.BeginBinaryImportAsync("""
            COPY kimbaldb_dbo.nameplate (guid,meterno,deviceid,manufacturer,firmwareversion,metertype,metercategory,rating,yearofmanufacture,ctratio,ptratio,createddate,nodeid,metertemplateid,ip,port,communicationmodule,blockcaptureperiod,installedon,originalinstalledon)
            FROM STDIN (FORMAT BINARY)
            """, ct))
        {
            foreach (long index in indices)
            {
                await copy.StartRowAsync(ct);
                await copy.WriteAsync(HesRegistrationDefinition.OwnershipId(index), NpgsqlDbType.Uuid, ct);
                await Text(copy, MeterRegistry.FormatSerial(index), ct);
                await Text(copy, HesRegistrationDefinition.DeviceId(index), ct);
                foreach (var value in new[] { d.Manufacturer, d.Firmware, d.MeterType, d.Category, d.Rating }) await Text(copy, value, ct);
                foreach (var value in new[] { d.Year, d.CtRatio, d.PtRatio }) await Number(copy, value, ct);
                await copy.WriteAsync(now, NpgsqlDbType.Timestamp, ct);
                await Text(copy, MeterNodeIds.Format(index), ct);
                await copy.WriteAsync((long)d.TemplateId, NpgsqlDbType.Bigint, ct);
                await Text(copy, MeterAddressing.ComputeAddress(d.AddressPrefix, index).ToString(), ct);
                await copy.WriteAsync(d.Port, NpgsqlDbType.Integer, ct);
                await Text(copy, d.Module, ct);
                await Number(copy, d.CapturePeriod, ct);
                await copy.WriteAsync(now, NpgsqlDbType.Timestamp, ct);
                await copy.WriteAsync(now, NpgsqlDbType.Timestamp, ct);
            }
            await copy.CompleteAsync(ct);
        }
        await using (var copy = await connection.BeginBinaryImportAsync("COPY kimbaldb_dbo.metersecurity (meterno,masterkey,globalkey,hlsussecret,hlsfwsecret,llsmrsecret,createddate) FROM STDIN (FORMAT BINARY)", ct))
        {
            foreach (long index in indices)
            {
                await copy.StartRowAsync(ct);
                await Text(copy, MeterRegistry.FormatSerial(index), ct);
                // Current simulator uses one fixed demo key profile; it has no separate master/FW keys.
                foreach (var value in new[] { d.GlobalKey, d.GlobalKey, d.HlsSecret, d.HlsSecret, d.LlsSecret }) await Text(copy, value, ct);
                await copy.WriteAsync(now, NpgsqlDbType.Timestamp, ct);
            }
            await copy.CompleteAsync(ct);
        }
        await using (var copy = await connection.BeginBinaryImportAsync("COPY kimbaldb_dbo.latestrouting (createddate,nodeid,gatewayid,sinkid,linkscore,lastcommunicatedon,sourceendpoint,hopcount,iscommunicating) FROM STDIN (FORMAT BINARY)", ct))
        {
            foreach (long index in indices)
            {
                await copy.StartRowAsync(ct);
                await copy.WriteAsync(now, NpgsqlDbType.Timestamp, ct);
                var route = d.RouteFor(index);
                foreach (var value in new[] { MeterNodeIds.Format(index), route.Gateway, route.Sink }) await Text(copy, value, ct);
                await copy.WriteAsync(1L, NpgsqlDbType.Bigint, ct);
                await copy.WriteAsync(now, NpgsqlDbType.Timestamp, ct);
                await copy.WriteAsync((long)d.Endpoint, NpgsqlDbType.Bigint, ct);
                await copy.WriteAsync(-1, NpgsqlDbType.Integer, ct);
                await copy.WriteAsync(false, NpgsqlDbType.Boolean, ct);
            }
            await copy.CompleteAsync(ct);
        }
    }

    private static async Task Text(NpgsqlBinaryImporter copy, string text, CancellationToken ct) => await copy.WriteAsync(text, NpgsqlDbType.Text, ct);
    private static async Task Number(NpgsqlBinaryImporter copy, int? value, CancellationToken ct)
    {
        if (value.HasValue) await copy.WriteAsync(value.Value, NpgsqlDbType.Integer, ct);
        else await copy.WriteNullAsync(ct);
    }
    private static void AddIdentities(NpgsqlCommand command, string[] nodes, string[] serials)
    {
        command.Parameters.AddWithValue("nodes", nodes);
        command.Parameters.AddWithValue("serials", serials);
    }
    private static IEnumerable<long[]> Chunks(HesRegistrationDefinition d)
    {
        for (long first = d.StartIndex; first <= d.EndIndex; first += ChunkSize)
            yield return Enumerable.Range(0, (int)Math.Min(ChunkSize, d.EndIndex - first + 1)).Select(n => first + n).ToArray();
    }
    private static async Task Execute(NpgsqlConnection connection, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync(ct);
    }
}
