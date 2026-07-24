using System;
using System.Text;

namespace MeterSimulator.Models
{
    /// <summary>
    /// DLMS identity for a meter.  This is the SINGLE source of truth for a meter's
    /// system title and cryptographic keys so the simulator (DLMS server) and any
    /// HES / test client derive IDENTICAL values — never two divergent schemes.
    /// HESTestClient references this same helper.
    ///
    /// Identity scheme (reverted to FIXED/shared 2026-07-24):
    ///   • systemTitle + all keys are the SAME for every meter, so a client configured
    ///     with these fixed values (e.g. GXDLMSDirector) can talk to any meter.
    ///   • ONLY the serial number stays per-index, so meters remain individually named
    ///     ("MY" + 9-digit index) and the HES can still tell them apart in the payload.
    ///
    /// (An earlier version derived per-meter keys from the index; that was reverted
    /// because the field/test HES uses a single fixed key set.)
    ///
    /// NOTE on the DLMS server (lower) address: it is intentionally NOT derived here.
    /// Routing to the right meter is done by IPv6 before the brain ever sees a frame, so
    /// the logical device address stays a fixed configured value (like a real meter's
    /// management logical device = 1) and the server accepts whatever the HES dials.
    /// </summary>
    public static class MeterIdentity
    {
        // Fixed, shared across all meters.  Return fresh copies so callers can't mutate
        // the shared source arrays (the DLMS ciphering layer may rewrite key buffers).
        private static readonly byte[] FixedSystemTitle = Encoding.ASCII.GetBytes("SIMULATR");          // 8 bytes
        private static readonly byte[] FixedKey16       = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");   // 16 bytes (GUEK/GAK/HLS)
        private static readonly byte[] FixedLlsKey      = Encoding.ASCII.GetBytes("12345678");           // 8 bytes

        /// <summary>Serial number string, matches ManyMeterSimulator MeterRegistry.FormatSerial.</summary>
        public static string Serial(long index) => $"MY{index:D9}";

        public static byte[] SystemTitle(long index)       => (byte[])FixedSystemTitle.Clone();
        public static byte[] BlockCipherKey(long index)    => (byte[])FixedKey16.Clone(); // GUEK
        public static byte[] AuthenticationKey(long index) => (byte[])FixedKey16.Clone(); // GAK
        public static byte[] HlsKey(long index)            => (byte[])FixedKey16.Clone();
        public static byte[] LlsKey(long index)            => (byte[])FixedLlsKey.Clone();
    }
}
