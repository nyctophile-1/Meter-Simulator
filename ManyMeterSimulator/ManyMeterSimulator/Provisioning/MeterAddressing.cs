using System.Net;
using System.Net.Sockets;

namespace ManyMeterSimulator.Provisioning;

/// <summary>Shared, correct address<->index math - used by MeterRegistry and any test tooling that needs to generate the same addresses.</summary>
public static class MeterAddressing
{
    /// <summary>
    /// Validates a meter address prefix. It must be an IPv6 <c>/64</c> network address (host bits
    /// zero), since <see cref="ComputeAddress"/> encodes the meter index into the low 64 bits. This
    /// is a per-deployment value — it must match the /64 actually routed to the host — so callers
    /// validate it at startup and fail fast rather than silently using a wrong prefix.
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
        if (parts.Length != 2 || !int.TryParse(parts[1], out int bits) || bits != 64)
        {
            error = $"'{addressPrefixCidr}' must be an IPv6 /64 (e.g. 'fd00:1234:5678::/64')";
            return false;
        }

        if (!IPAddress.TryParse(parts[0], out IPAddress? ip) || ip.AddressFamily != AddressFamily.InterNetworkV6)
        {
            error = $"'{addressPrefixCidr}' is not a valid IPv6 address";
            return false;
        }

        // A /64 network address has its low 64 bits (the host portion) zero.
        byte[] hostBytes = ip.GetAddressBytes()[8..16];
        if (Array.Exists(hostBytes, b => b != 0))
        {
            error = $"'{addressPrefixCidr}' has non-zero host bits; use the network address, e.g. '{ip.GetAddressBytes()[0]:x2}..::/64'";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Builds the Nth address in a /64 prefix by treating the network prefix's own address as a
    /// 128-bit value and setting the low 64 bits to the index, then re-encoding via IPAddress
    /// (which handles "::" compression correctly per RFC 5952). Deliberately NOT string
    /// concatenation (`$"{prefix}{index:x}"`) - that treats the index as a single 16-bit IPv6
    /// group, which produces an invalid address (and throws) past 65,535.
    /// </summary>
    public static IPAddress ComputeAddress(string addressPrefixCidr, long index)
    {
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), "Meter index cannot be negative.");
        }

        byte[] bytes = IPAddress.Parse(StripCidrSuffix(addressPrefixCidr)).GetAddressBytes();
        byte[] indexBytes = BitConverter.GetBytes((ulong)index);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(indexBytes);
        }

        Array.Copy(indexBytes, 0, bytes, 8, 8); // host portion = last 8 bytes (64 bits) of a /64
        return new IPAddress(bytes);
    }

    /// <summary>Inverse of ComputeAddress - recovers the index from an address, assuming it's within the given /64.</summary>
    public static long ExtractIndex(IPAddress address)
    {
        byte[] hostBytes = address.GetAddressBytes()[8..16];
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(hostBytes);
        }

        return (long)BitConverter.ToUInt64(hostBytes);
    }

    public static string StripCidrSuffix(string addressPrefixCidr) => addressPrefixCidr.Split('/')[0];
}
