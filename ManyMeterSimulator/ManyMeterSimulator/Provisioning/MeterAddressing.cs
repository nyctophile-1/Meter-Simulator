using System.Net;
using System.Net.Sockets;

namespace ManyMeterSimulator.Provisioning;

/// <summary>Shared, correct address<->index math - used by MeterRegistry and any test tooling that needs to generate the same addresses.</summary>
public static class MeterAddressing
{
    /// <summary>
    /// Widest prefix accepted: the meter index occupies the low 48 bits, so anything up to a /80
    /// leaves the index untouched. /80 specifically is what AWS hands out for ENI IPv6 prefix
    /// delegation, which is how the meter range is routed in production (see deploy_task.md R-4).
    /// </summary>
    public const int MaxPrefixLength = 80;

    /// <summary>Bits of the address reserved for the meter index — the low 48.</summary>
    private const int IndexBits = 48;

    /// <summary>Byte offset where the index starts (128 - 48 = bit 80 = byte 10).</summary>
    private const int IndexByteOffset = 16 - (IndexBits / 8);

    /// <summary>Largest index the address scheme can encode. Far above <c>MeterRegistry.MaxIndex</c>.</summary>
    public const long MaxEncodableIndex = (1L << IndexBits) - 1;

    /// <summary>
    /// Validates a meter address prefix. It must be an IPv6 network address between <c>/64</c> and
    /// <c>/80</c> with all bits below the prefix length zero, since <see cref="ComputeAddress"/>
    /// encodes the meter index into the low 48 bits. This is a per-deployment value — it must match
    /// the prefix actually routed to the host — so callers validate it at startup and fail fast
    /// rather than silently using a wrong prefix.
    ///
    /// The /64..*/80* range exists because the two ways to route a meter range to a host differ:
    /// a kernel `local` route takes a /64, while AWS ENI prefix delegation issues a /80.
    /// </summary>
    public static bool TryValidatePrefix(string? addressPrefixCidr, out string error)
    {
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(addressPrefixCidr))
        {
            error = "the address prefix is not set";
            return false;
        }

        string[] parts = addressPrefixCidr.Split('/');
        if (parts.Length != 2 || !int.TryParse(parts[1], out int bits) || bits < 64 || bits > MaxPrefixLength)
        {
            error = $"'{addressPrefixCidr}' must be an IPv6 prefix between /64 and /{MaxPrefixLength} " +
                    "(e.g. 'fd00:1234:5678::/64' or '2406:da1a:1c29:500:1a2b::/80')";
            return false;
        }

        if (!IPAddress.TryParse(parts[0], out IPAddress? ip) || ip.AddressFamily != AddressFamily.InterNetworkV6)
        {
            error = $"'{addressPrefixCidr}' is not a valid IPv6 address";
            return false;
        }

        if (HasHostBitsSet(ip.GetAddressBytes(), bits))
        {
            error = $"'{addressPrefixCidr}' has non-zero host bits; use the network address of the prefix";
            return false;
        }

        return true;
    }

    /// <summary>True if any bit at or below <paramref name="prefixBits"/> is set.</summary>
    private static bool HasHostBitsSet(byte[] bytes, int prefixBits)
    {
        int wholeBytes = prefixBits / 8;
        int leftoverBits = prefixBits % 8;

        if (leftoverBits != 0)
        {
            // Within the straddling byte, the low (8 - leftoverBits) bits belong to the host.
            if ((bytes[wholeBytes] & (0xFF >> leftoverBits)) != 0)
            {
                return true;
            }

            wholeBytes++;
        }

        for (int i = wholeBytes; i < bytes.Length; i++)
        {
            if (bytes[i] != 0)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Builds the Nth address in the prefix by taking the prefix's own bytes and writing the index
    /// into the low <see cref="IndexBits"/> bits (bytes 10..15), leaving bytes 0..9 untouched.
    /// Re-encoded via IPAddress, which handles "::" compression correctly per RFC 5952.
    ///
    /// Deliberately NOT string concatenation (`$"{prefix}{index:x}"`) — that treats the index as a
    /// single 16-bit IPv6 group, producing an invalid address (and throwing) past 65,535.
    ///
    /// Writing only the low 48 bits — rather than the low 64 — is what lets the same math serve both
    /// a /64 (kernel `local` route) and a /80 (AWS ENI prefix delegation): bytes 8..9 belong to the
    /// prefix under a /80 and must survive. For every index in the supported range the top two bytes
    /// of a 64-bit index are zero anyway, so /64 addresses are bit-for-bit identical to before.
    /// </summary>
    public static IPAddress ComputeAddress(string addressPrefixCidr, long index)
    {
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), "Meter index cannot be negative.");
        }

        if (index > MaxEncodableIndex)
        {
            throw new ArgumentOutOfRangeException(
                nameof(index),
                $"Meter index {index} exceeds the {IndexBits}-bit address space (max {MaxEncodableIndex}).");
        }

        byte[] bytes = IPAddress.Parse(StripCidrSuffix(addressPrefixCidr)).GetAddressBytes();

        // Big-endian low 48 bits of the index into bytes 10..15.
        for (int i = 0; i < IndexBits / 8; i++)
        {
            bytes[IndexByteOffset + i] = (byte)(index >> (IndexBits - 8 * (i + 1)));
        }

        return new IPAddress(bytes);
    }

    /// <summary>
    /// Inverse of <see cref="ComputeAddress"/> — recovers the index from an address, assuming it
    /// falls within the configured prefix. Reads only the low 48 bits, mirroring ComputeAddress, so
    /// the prefix length doesn't need to be threaded through every caller.
    /// </summary>
    public static long ExtractIndex(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();

        long index = 0;
        for (int i = IndexByteOffset; i < bytes.Length; i++)
        {
            index = (index << 8) | bytes[i];
        }

        return index;
    }

    public static string StripCidrSuffix(string addressPrefixCidr) => addressPrefixCidr.Split('/')[0];
}
