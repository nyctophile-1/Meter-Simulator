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

    /// <summary>
    /// File name of the operator-set runtime config within <see cref="Folder"/> (network delay
    /// and any future knobs). A separate file from the batch store so the two never share a
    /// failure: a corrupt config file falls back to defaults, a corrupt batch store is fatal.
    /// </summary>
    public string RuntimeConfigFileName { get; set; } = "maya-runtime-config.json";

    /// <summary>
    /// File name of the network registry (brokers and HES push targets) within <see cref="Folder"/>.
    /// Shares the BATCH store's fail-fast-on-corrupt policy rather than the runtime config's
    /// fall-back-to-defaults one: a lost registry leaves every batch bound to keys that no longer
    /// resolve, which is silent rather than merely degraded (network_registry.md §3.4).
    /// </summary>
    public string NetworkRegistryFileName { get; set; } = "network.json";

    /// <summary>
    /// Folder within <see cref="Folder"/> holding the ASP.NET Data Protection key ring that encrypts
    /// broker passwords. Pinned explicitly because the default key location is per-user: a redeploy
    /// that runs the app under a different account would otherwise silently lose every stored
    /// password, surfacing much later as a broker that will not authenticate.
    /// </summary>
    public string KeyRingFolderName { get; set; } = "keys";
}
