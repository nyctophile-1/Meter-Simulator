using System.Data.Common;
using Microsoft.Data.SqlClient;
using Npgsql;

namespace ManyMeterSimulator.Networking.Registry;

public enum DatabaseProvider { SqlServer, PostgreSql }

/// <summary>Operator-managed database endpoint. Credentials are encrypted by the network store.</summary>
public sealed record DatabaseConnection
{
    public string Key { get; init; } = "";
    public DatabaseProvider Provider { get; init; }
    public string ConnectionString { get; init; } = "";

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Key) || Key != Key.Trim())
            throw new ArgumentException("A database connection needs a name without surrounding spaces.");
        if (string.IsNullOrWhiteSpace(ConnectionString))
            throw new ArgumentException("Enter a connection string.");
        try { using var connection = CreateConnection(); }
        catch (ArgumentException) { throw new ArgumentException("Invalid connection string for the selected database provider."); }
    }

    public DbConnection CreateConnection() => Provider switch
    {
        DatabaseProvider.SqlServer => new SqlConnection(new SqlConnectionStringBuilder(ConnectionString)
        { ConnectTimeout = 10, Pooling = false }.ConnectionString),
        DatabaseProvider.PostgreSql => new NpgsqlConnection(new NpgsqlConnectionStringBuilder(ConnectionString)
        { Timeout = 10, CommandTimeout = 10, Pooling = false }.ConnectionString),
        _ => throw new ArgumentException("Unsupported database provider."),
    };
}

/// <summary>Checks authentication and a read-only round trip, without changing HES data.</summary>
public sealed class DatabaseConnectionProber
{
    public async Task<bool> TestAsync(DatabaseConnection endpoint, CancellationToken cancellationToken = default)
    {
        endpoint.Validate();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            await using var connection = endpoint.CreateConnection();
            await connection.OpenAsync(timeout.Token);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT 1";
            command.CommandTimeout = 10;
            return Convert.ToInt32(await command.ExecuteScalarAsync(timeout.Token)) == 1;
        }
        catch (Exception ex) when (ex is DbException or OperationCanceledException or TimeoutException)
        {
            // Driver errors can include connection details; never send them to the browser or logs.
            return false;
        }
    }
}
