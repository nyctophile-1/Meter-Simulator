namespace ManyMeterSimulator.Networking.Registry;

/// <summary>
/// One named MQTT broker a batch can be bound to (network_registry.md §3).
///
/// In the field the broker details live in different places per NIC — a Wirepas/Kmesh gateway holds
/// them, a 4G meter has them written into its OBIS objects — but from the simulator's side they are
/// the same five values, so one shape serves every MQTT NIC.
///
/// <para>
/// The <see cref="Key"/> is the operator's label and the join key batches store. It is immutable
/// once created: renaming would silently orphan every batch pointing at it, and there is no second
/// identifier to fall back on.
/// </para>
/// </summary>
public sealed class BrokerEndpoint
{
    public required string Key { get; init; }

    public required string Host { get; init; }

    public int Port { get; init; } = 1883;

    public string Username { get; init; } = string.Empty;

    /// <summary>
    /// Plaintext in memory, encrypted at rest — see <see cref="ISecretProtector"/>. Never rendered
    /// back to the UI and never logged (the MQTT client logs credential names only).
    /// </summary>
    /// <remarks>
    /// Settable (not init-only) so <see cref="JsonNetworkRegistryStore"/> can swap ciphertext for
    /// plaintext as it loads, without the whole row needing to be rebuilt.
    /// </remarks>
    public string Password { get; set; } = string.Empty;

    public bool UseTls { get; init; }

    /// <summary>
    /// The operational kill switch. A disabled endpoint contributes no bindings, so its clients are
    /// torn down by the normal reconcile pass — this is what replaced the per-transport
    /// <c>Nics:&lt;x&gt;:Enabled</c> flags, which could not express "silence one broker of several"
    /// (network_registry.md §5.6).
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// False for a row saved through the admin "save unverified" path — a broker that could not be
    /// reached at the time it was added. Kept distinct from "probe currently failing" so an endpoint
    /// that has never once connected is never mistaken for one that is merely down right now.
    /// </summary>
    public bool Verified { get; set; }

    /// <summary>When a probe (or the live client) last confirmed this endpoint reachable.</summary>
    public DateTimeOffset? LastVerifiedUtc { get; set; }

    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>How this endpoint reads in a log line — never includes the password.</summary>
    public string Describe() => $"{Key} ({Host}:{Port}{(UseTls ? ", TLS" : string.Empty)})";
}
