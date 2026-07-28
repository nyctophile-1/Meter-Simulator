namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// Where the batch registry is persisted so batches, their status, and the allocation cursor
/// survive restarts, reboots, and redeployments. Bound from the "Persistence" config section.
/// </summary>
public sealed class PersistenceOptions
{
    public const string SectionName = "Persistence";

    /// <summary>
    /// Folder holding the batch store file. Relative paths resolve against the app content root, so
    /// the default <c>../data</c> lands in the PARENT of the deployment folder — a sibling of the
    /// app, alongside <c>logs/</c> (see Program.cs). A redeploy replaces the app folder but never
    /// touches this sibling, so batches survive with no hardcoded absolute path. The folder is
    /// created if missing, so the first deployment needs no manual setup. Override per deployment
    /// via the environment variable <c>Persistence__Folder</c> only if a different location is wanted.
    /// </summary>
    public string Folder { get; set; } = "../data";

    /// <summary>File name of the JSON batch store within <see cref="Folder"/>.</summary>
    public string FileName { get; set; } = "batches.json";
}
