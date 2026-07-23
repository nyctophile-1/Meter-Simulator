using System;
using System.Buffers.Binary;
using System.Text;

namespace MeterSimulator.Models
{
    /// <summary>
    /// Deterministic per-meter DLMS identity derived from the meter's stable index —
    /// the host portion of its IPv6 address (see ManyMeterSimulator.Provisioning.MeterAddressing).
    ///
    /// This is the SINGLE source of truth for a meter's system title and cryptographic
    /// keys so the simulator (DLMS server) and any HES / test client derive IDENTICAL
    /// values from the same index — never two divergent schemes. HESTestClient references
    /// this same helper (task 13).
    ///
    /// Scheme (simple + replicable — deliberately NOT a real KDF; a real HES would get
    /// per-meter keys from its own key management, and must be told these to interop):
    ///   systemTitle(8) = "SIM"(3 ASCII) + big-endian low 5 bytes of index
    ///   16-byte key    = 8-char ASCII label + big-endian 8 bytes of index
    ///   llsKey(8)      = big-endian 8 bytes of index
    ///
    /// NOTE on the DLMS server (lower) address: it is intentionally NOT derived here.
    /// Routing to the right meter is done by IPv6 before the brain ever sees a frame, so
    /// the logical device address stays a fixed configured value (like a real meter's
    /// management logical device = 1) and the server accepts whatever the HES dials.
    /// What is genuinely per-meter is the crypto identity below.
    /// </summary>
    public static class MeterIdentity
    {
        private static readonly byte[] Manufacturer = Encoding.ASCII.GetBytes("SIM"); // 3 bytes

        /// <summary>Serial number string, matches ManyMeterSimulator MeterRegistry.FormatSerial.</summary>
        public static string Serial(long index) => $"MY{index:D9}";

        public static byte[] SystemTitle(long index)
        {
            var st = new byte[8];
            Manufacturer.CopyTo(st, 0);                     // bytes 0..2
            Span<byte> idx = stackalloc byte[8];
            BinaryPrimitives.WriteInt64BigEndian(idx, index);
            idx.Slice(3, 5).CopyTo(st.AsSpan(3));           // low 5 bytes of index → bytes 3..7
            return st;
        }

        public static byte[] BlockCipherKey(long index)    => Key16("GUEKSIM_", index); // GUEK
        public static byte[] AuthenticationKey(long index) => Key16("GAK_SIM_", index); // GAK
        public static byte[] HlsKey(long index)            => Key16("HLS_SIM_", index);

        public static byte[] LlsKey(long index)
        {
            var k = new byte[8];
            BinaryPrimitives.WriteInt64BigEndian(k, index);
            return k;
        }

        // label8 must be exactly 8 ASCII chars.
        private static byte[] Key16(string label8, long index)
        {
            var key = new byte[16];
            Encoding.ASCII.GetBytes(label8).CopyTo(key, 0);              // bytes 0..7
            BinaryPrimitives.WriteInt64BigEndian(key.AsSpan(8), index);  // bytes 8..15
            return key;
        }
    }
}
