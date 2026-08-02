namespace ManyMeterSimulator.Settings;

/// <summary>
/// Durable home for operator-set runtime config.
///
/// Mutation goes through <see cref="Update"/> rather than a Save(document) call on purpose: each
/// consumer owns one section, and read-modify-write of the whole document would let two settings
/// classes overwrite each other's section. Update applies the change to the single shared document
/// under a lock, so adding a second knob later cannot silently erase the first.
/// </summary>
public interface IRuntimeConfigStore
{
    /// <summary>The document as last loaded or saved. Read sections from this at construction.</summary>
    MayaRuntimeConfig Current { get; }

    /// <summary>
    /// Applies <paramref name="mutate"/> to the document and persists it. Never throws for I/O
    /// problems - a failed write is logged, because a full disk should not stop a live setting
    /// change from taking effect in memory.
    /// </summary>
    void Update(Action<MayaRuntimeConfig> mutate);
}
