using System.Security.Claims;
using System.Text.Json;
using ManyMeterSimulator.Auth;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Registry;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Provisioning;

public sealed class HesRegistrationPreview
{
    internal HesRegistrationPreview() { }
    internal DatabaseConnection Database { get; init; } = default!;
    internal MeterBatch Batch { get; init; } = default!;
    internal HesRegistrationDefinition Definition { get; init; } = default!;
    internal string Owner { get; init; } = "";
    internal string? EnvironmentKey { get; init; }
    internal int Consumed;
    public required RegistrationInspection Inspection { get; init; }
    public DateTimeOffset ExpiresAt { get; init; } = DateTimeOffset.UtcNow.AddMinutes(5);
    public string BatchName => Batch.Name;
    public long Count => Definition.Count;
    public string FirstNode => MeterNodeIds.Format(Definition.StartIndex);
    public string LastNode => MeterNodeIds.Format(Definition.EndIndex);
    public string Category => Definition.Category;
    public string MeterType => Definition.MeterType;
    public int TemplateId => Definition.TemplateId;
    public string ModelHash => Definition.ModelHash;
    public string Route => $"{Definition.Gateway} / {Definition.Sink}; endpoint {Definition.Endpoint}";
    public string FirstAddress => MeterAddressing.ComputeAddress(Definition.AddressPrefix, Definition.StartIndex).ToString();
    public int Port => Definition.Port;
}

public sealed record HesRegistrationReceipt(Guid OperationId, string State, string Target, int BatchId,
    string FirstNode, string LastNode, long Count, int TemplateId, string ModelHash, string ConfigurationHash,
    RegistrationCounts Removed, RegistrationCounts Inserted, DateTimeOffset AtUtc, string? Warning = null);

public sealed class HesBatchRegistrationService(MeterRegistry meters, NetworkRegistry network,
    HesRegistrationDefinitionFactory definitions, HesRegistrationDatabase database, SessionRegistry sessions,
    IOptions<PersistenceOptions> persistence, IHostEnvironment host, ILogger<HesBatchRegistrationService> logger)
{
    public async Task<HesRegistrationPreview> PreviewAsync(ClaimsPrincipal user, int batchId, string databaseKey, int templateId, CancellationToken ct)
    {
        string owner = RequireAdmin(user);
        var batch = meters.Batches.SingleOrDefault(b => b.Id == batchId)
            ?? throw new InvalidOperationException("Select an existing batch.");
        using var lease = meters.AcquireRegistrationLease(batch);
        CheckSessions(batch);
        var connection = network.Databases.SingleOrDefault(d => d.Key == databaseKey)
            ?? throw new InvalidOperationException("Select a saved database connection.");
        var definition = definitions.Create(batch, templateId);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(15));
        return new()
        {
            Database = connection, Batch = batch, Definition = definition, Owner = owner, EnvironmentKey = batch.EnvironmentKey,
            Inspection = await database.PreviewAsync(connection, definition, timeout.Token)
        };
    }

    public async Task<HesRegistrationReceipt> ReplaceAsync(ClaimsPrincipal user, HesRegistrationPreview preview, bool adoptLegacy, CancellationToken ct)
    {
        if (RequireAdmin(user) != preview.Owner) throw new UnauthorizedAccessException("Preview belongs to another administrator.");
        if (preview.ExpiresAt <= DateTimeOffset.UtcNow || Interlocked.Exchange(ref preview.Consumed, 1) != 0)
            throw new InvalidOperationException("Preview has expired or was already used. Preview again.");
        using var lease = meters.AcquireRegistrationLease(preview.Batch);
        CheckSessions(preview.Batch);
        var current = network.Databases.SingleOrDefault(d => d.Key == preview.Database.Key);
        if (current != preview.Database || preview.Batch.EnvironmentKey != preview.EnvironmentKey ||
            definitions.Create(preview.Batch, preview.TemplateId).Fingerprint != preview.Definition.Fingerprint)
            throw new InvalidOperationException("Batch, model or connection changed. Preview again.");
        if (preview.Inspection.Conflicts > 0 || preview.Inspection.LegacyMeters > 0 && !adoptLegacy)
            throw new InvalidOperationException("Resolve ownership conflicts before replacement.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(15));
        Guid operation = Guid.NewGuid();
        var receipt = new HesRegistrationReceipt(operation, "Started", preview.Inspection.Target, preview.Batch.Id,
            preview.FirstNode, preview.LastNode, preview.Count, preview.TemplateId, preview.ModelHash, preview.Definition.Fingerprint,
            preview.Inspection.Existing, new(0, 0, 0), DateTimeOffset.UtcNow);
        await SaveReceipt(receipt);
        try
        {
            await database.ReplaceAsync(preview.Database, preview.Definition, preview.Inspection, adoptLegacy, timeout.Token);
            receipt = receipt with { State = "Database provisioned; HES verification pending", Inserted = new(preview.Count, preview.Count, preview.Count), AtUtc = DateTimeOffset.UtcNow };
        }
        catch (RegistrationCommitUncertainException)
        {
            await SaveOutcomeBestEffort(receipt with { State = "Commit outcome unknown; verify before retry", AtUtc = DateTimeOffset.UtcNow });
            throw;
        }
        catch
        {
            await SaveOutcomeBestEffort(receipt with { State = "Not committed", AtUtc = DateTimeOffset.UtcNow });
            throw;
        }
        bool saved = await SaveOutcomeBestEffort(receipt);
        logger.LogInformation("HES batch registration {OperationId}: {Count} meters provisioned in {Target}", operation, preview.Count, receipt.Target);
        return saved ? receipt : receipt with { Warning = "Database committed, but the local completion receipt could not be saved." };
    }

    private void CheckSessions(MeterBatch batch)
    {
        if (sessions.Snapshot().Any(s => s.Meter.Index >= batch.StartIndex && s.Meter.Index <= batch.EndIndex))
            throw new InvalidOperationException("Wait for this batch's active connections to close before provisioning.");
    }
    private static string RequireAdmin(ClaimsPrincipal user)
    {
        if (user.Identity?.IsAuthenticated != true || !user.IsInRole(AppRoles.Admin))
            throw new UnauthorizedAccessException("Only administrators can provision HES batches.");
        return user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.Identity.Name
            ?? throw new UnauthorizedAccessException("Administrator identity is missing.");
    }
    private async Task SaveReceipt(HesRegistrationReceipt receipt)
    {
        string root = Path.IsPathRooted(persistence.Value.Folder) ? persistence.Value.Folder : Path.Combine(host.ContentRootPath, persistence.Value.Folder);
        string folder = Path.Combine(root, "hes-registration-receipts");
        Directory.CreateDirectory(folder);
        string path = Path.Combine(folder, receipt.OperationId + ".json");
        await File.WriteAllTextAsync(path + ".tmp", JsonSerializer.Serialize(receipt, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(path + ".tmp", path, true);
    }
    private async Task<bool> SaveOutcomeBestEffort(HesRegistrationReceipt receipt)
    {
        try { await SaveReceipt(receipt); return true; }
        catch { logger.LogWarning("Unable to save completion receipt for HES registration {OperationId}", receipt.OperationId); return false; }
    }
}
