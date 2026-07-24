using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace MeterSimulator.Models
{
    /// <summary>
    /// One simulated meter's identity + live value store. Every meter shares one FIXED demo
    /// cryptographic identity — keys "AAAA…" and a "SIM"+serverAddress system title — so a
    /// DLMS client / HES (e.g. GXDLMSDirector) configured with the demo keys can associate with
    /// any meter unchanged. Only the serial (<see cref="MeterNo"/>) is per-meter.
    /// </summary>
    public class DLMSMeter
    {
        /// <summary>Stable per-meter index = IPv6 host portion. The meter's durable identity.</summary>
        public long Index { get; }

        public string MeterNo { get; }
        public string LogicalName { get; }

        public int ClientAddress { get; }
        public int ServerAddress { get; }

        // Fixed demo crypto identity — shared by all meters.
        public byte[]? SystemTitle { get; }
        public byte[]? AuthenticationKey { get; }
        public byte[]? BlockCipherKey { get; }
        public byte[]? HLSKey { get; }
        public byte[]? LLSKey { get; }

        // Demo keys: block-cipher (GUEK), authentication (GAK) and HLS secret are all "AAAA…" (16
        // bytes); LLS secret is "12345678" (8 bytes). Configure the HES with the same values.
        private static byte[] DemoKey16() => Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");

        private readonly Dictionary<string, object?> _values = new();

        public DLMSMeter(
            long index,
            string logicalName,
            int clientAddress,
            int serverAddress)
        {
            Index = index;
            MeterNo = MeterIdentity.Serial(index);   // "MY" + 9 digits, matches MeterRegistry
            LogicalName = logicalName;
            ClientAddress = clientAddress;
            ServerAddress = serverAddress;

            SystemTitle       = BuildSystemTitle(serverAddress);
            AuthenticationKey = DemoKey16();
            BlockCipherKey    = DemoKey16();
            HLSKey            = DemoKey16();
            LLSKey            = Encoding.ASCII.GetBytes("12345678");
        }

        /// <summary>8-byte system title: "SIM" (3) + 0x00 pad + 4 big-endian bytes of the server address.</summary>
        private static byte[] BuildSystemTitle(int serverAddress)
        {
            var st = new byte[8];
            Encoding.ASCII.GetBytes("SIM").CopyTo(st, 0);          // bytes 0..2
            st[3] = 0x00;                                          // byte 3 pad
            BinaryPrimitives.WriteInt32BigEndian(st.AsSpan(4), serverAddress); // bytes 4..7
            return st;
        }

        public void SetValue(string obis, object? value)
        {
            _values[obis] = value;
        }

        public object? GetValue(string obis)
        {
            _values.TryGetValue(obis, out var value);
            return value;
        }

        public IReadOnlyDictionary<string, object?> GetAllValues()
            => _values;
    }
}
