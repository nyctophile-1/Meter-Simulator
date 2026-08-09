using System.Net;
using System.Net.Sockets;

namespace ManyMeterSimulator.Networking.Registry;

/// <summary>
/// One named HES TCP push listener a 4G TCP batch can push to (network_registry.md §6).
///
/// Only the outbound direction uses this. Inbound TCP is broker-agnostic and needs no registry at
/// all — HES dials the meter's own address and the reply goes back down the same socket, so the
/// socket is already the correlation (network_registry.md §5.0).
/// </summary>
public sealed class PushTargetEndpoint
{
    public required string Key { get; init; }

    /// <summary>
    /// IPv6 only — see <see cref="TryParseAddress"/>. Held as a string because that is what
    /// round-trips through JSON cleanly; parse with <see cref="TryParseAddress"/> when dialling.
    /// </summary>
    public required string Address { get; init; }

    public int Port { get; init; } = 4059;

    /// <summary>See <see cref="BrokerEndpoint.Enabled"/>.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>See <see cref="BrokerEndpoint.Verified"/>.</summary>
    public bool Verified { get; set; }

    public DateTimeOffset? LastVerifiedUtc { get; set; }

    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// The form <see cref="ManyMeterSimulator.Brain.PushCoordinator"/> already accepts.
    /// Bracketed because a bare IPv6 literal followed by ":port" is ambiguous with its own colons.
    /// </summary>
    public string Destination => $"[{Address}]:{Port}";

    public string Describe() => $"{Key} ({Destination})";

    /// <summary>
    /// Parses an operator-entered address, accepting IPv6 only.
    ///
    /// IPv4 is rejected rather than quietly stored: the fleet lives in a routed IPv6 /64
    /// (<c>Tcp:AddressPrefix</c>), so a push from a meter in that prefix to an IPv4 listener has no
    /// source address for the far end to correlate on. Accepting one would persist a target that
    /// cannot work, and the failure would surface much later as "pushes arrive from nowhere".
    /// </summary>
    public static bool TryParseAddress(string? value, out IPAddress? address, out string error)
    {
        address = null;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(value))
        {
            error = "Enter an IPv6 address.";
            return false;
        }

        // Strip brackets so a pasted "[fd00::1]" is accepted as readily as a bare literal.
        string trimmed = value.Trim().Trim('[', ']');

        if (!IPAddress.TryParse(trimmed, out IPAddress? parsed))
        {
            error = $"'{trimmed}' is not a valid IP address.";
            return false;
        }

        if (parsed.AddressFamily != AddressFamily.InterNetworkV6)
        {
            error = $"'{trimmed}' is IPv4. Push targets must be IPv6 — the meter fleet is addressed " +
                    "from an IPv6 prefix, so an IPv4 listener has no source address to correlate on.";
            return false;
        }

        address = parsed;
        return true;
    }
}
