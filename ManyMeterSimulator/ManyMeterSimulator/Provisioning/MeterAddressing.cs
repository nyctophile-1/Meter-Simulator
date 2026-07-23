using System.Net;

namespace ManyMeterSimulator.Provisioning;

/// <summary>Shared, correct address<->index math - used by MeterRegistry and any test tooling that needs to generate the same addresses.</summary>
public static class MeterAddressing
{
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
