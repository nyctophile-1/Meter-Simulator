using System.Buffers.Binary;

namespace ManyMeterSimulator.Networking.CustomPush;

/// <summary>
/// Historical template-93 golden fixture. Production encoding uses HES metadata.
/// </summary>
public static class Template93
{
    public const int HesTemplateId = 93;
    public const uint MagicNumber = 0x0011090E;
    public const int ProfileHeaderLength = 11;
    public const int Daily1PDataLength = 20;

    public static byte[] BuildEsw(DateTimeOffset utcNow, string eventStatusWord)
    {
        MeterSimulator.Models.EventStatusWord.Validate(eventStatusWord);
        var payload = new byte[ProfileHeaderLength + 22];
        payload[0] = 5;
        payload[1] = 1;
        // The custom HES reader subtracts 330 minutes from this wall-clock epoch.
        uint rtc = checked((uint)utcNow.AddMinutes(330).ToUnixTimeSeconds());
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(ProfileHeaderLength), rtc);
        payload[15] = 4;
        payload[16] = 128;
        for (int bit = 0; bit < eventStatusWord.Length; bit++)
            if (eventStatusWord[bit] == '1') payload[17 + bit / 8] |= (byte)(1 << (7 - bit % 8));
        return payload;
    }

    /// <summary>
    /// Creates <c>DAILY_CUSTOM_PUSH_1P</c>: profile header, HES wall-clock timestamp, then four scaled
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
        payload[0] = 0x07; // HES NonDLMSProfileType.DAILYLOADPROFILE; 0x05 dispatches to ESW.
        payload[1] = 0x01; // one frame, clock-status 0
        // Captured RF daily push has meter alpha, meter number, and reserved bytes as zero.

        uint unixSeconds = checked((uint)utcNow.AddMinutes(330).ToUnixTimeSeconds());
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(ProfileHeaderLength), unixSeconds);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(ProfileHeaderLength + 4), importKwh);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(ProfileHeaderLength + 8), importKvah);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(ProfileHeaderLength + 12), exportKwh);
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(ProfileHeaderLength + 16), exportKvah);
        return payload;
    }
}
