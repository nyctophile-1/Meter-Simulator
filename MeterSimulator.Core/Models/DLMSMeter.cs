using System;
using System.Collections.Generic;

namespace MeterSimulator.Models
{
    /// <summary>
    /// One simulated meter's authoritative identity + live value store. Built ONCE from
    /// the meter's stable index (the host portion of its IPv6 address) — the crypto
    /// identity (system title, keys) is derived per-meter from that index via
    /// <see cref="MeterIdentity"/>, so it is distinct per meter and reproducible by the HES.
    /// </summary>
    public class DLMSMeter
    {
        /// <summary>Stable per-meter index = IPv6 host portion. The meter's durable identity.</summary>
        public long Index { get; }

        public string MeterNo { get; }
        public string LogicalName { get; }

        public int ClientAddress { get; }
        public int ServerAddress { get; }

        // Per-meter cryptographic identity, derived from Index (see MeterIdentity).
        public byte[]? SystemTitle { get; }
        public byte[]? AuthenticationKey { get; }
        public byte[]? BlockCipherKey { get; }
        public byte[]? HLSKey { get; }
        public byte[]? LLSKey { get; }

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

            SystemTitle       = MeterIdentity.SystemTitle(index);
            AuthenticationKey = MeterIdentity.AuthenticationKey(index);
            BlockCipherKey    = MeterIdentity.BlockCipherKey(index);
            HLSKey            = MeterIdentity.HlsKey(index);
            LLSKey            = MeterIdentity.LlsKey(index);
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
