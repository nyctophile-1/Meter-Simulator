using System.Buffers.Binary;

namespace ManyMeterSimulator.Networking.CustomPush;

/// <summary>
/// Custom scheduled-push encoder for EQA HES meter template 93 (Anvil-AMI 1&amp;2 RF).
/// Keep every template-93 category/profile encoder in this class as each is verified. Today the
/// only verified layout is the 1P daily scheduled push observed in RF traffic and EQA metadata.
/// </summary>
public static class Template93
{
    public const int HesTemplateId = 93;
    public const uint MagicNumber = 0x0011090E;
    public const int ProfileHeaderLength = 11;
    public const int Daily1PDataLength = 20;

    /// <summary>
    /// Creates <c>DAILY_CUSTOM_PUSH_1P</c>: profile header, UTC timestamp, then four scaled
    /// <c>UInt32</c> cumulative energy fields. HES applies the EQA -3 scalar to each energy value.
    /// </summary>
    public static byte[] BuildDaily1P(long meterIndex, DateTimeOffset utcNow)
    {
        if (meterIndex <= 0) throw new ArgumentOutOfRangeException(nameof(meterIndex));

        // Deterministic per-meter values allow custom payloads before a matching XML is available.
        uint importKwh = checked((uint)(100_000 + meterIndex * 1_000));
        uint importKvah = checked(importKwh + 10_000);
        uint exportKwh = checked((uint)(meterIndex % 10_000));
        uint exportKvah = checked(exportKwh + 100);

        var payload = new byte[ProfileHeaderLength + Daily1PDataLength];
        payload[0] = 0x05; // verified RF profile-type byte for this daily scheduled push
        payload[1] = 0x01; // one frame, clock-status 0
        // Captured RF daily push has meter alpha, meter number, and reserved bytes as zero.

        uint unixSeconds = checked((uint)utcNow.ToUnixTimeSeconds());
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(ProfileHeaderLength), unixSeconds);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(ProfileHeaderLength + 4), importKwh);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(ProfileHeaderLength + 8), importKvah);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(ProfileHeaderLength + 12), exportKwh);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(ProfileHeaderLength + 16), exportKvah);
        return payload;
    }
}
