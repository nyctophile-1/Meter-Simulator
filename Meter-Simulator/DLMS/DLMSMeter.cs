using System;
using System.Collections.Generic;
using System.Text;

namespace MeterSimulator.DLMS
{
    public class DLMSMeter
    {
        public string MeterNo { get; }
        public string LogicalName { get; }

        public int ClientAddress { get; }
        public int ServerAddress { get; }
        //public byte[]? MasterKey { get; } = Encoding.ASCII.GetBytes("AAAAAAAA");
        public byte[]? SystemTitle { get; } = Encoding.ASCII.GetBytes("SIMULATR");
        public byte[]? AuthenticationKey { get; } = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
        public byte[]? BlockCipherKey { get; } = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
        public string LlsPassword { get; } = "12345678";
        //public byte[]? HlsUsKey { get; } = Encoding.ASCII.GetBytes("AAAAAAAA");
        //public byte[]? HlsFwKey { get; } = Encoding.ASCII.GetBytes("AAAAAAAA");
        private readonly Dictionary<string, object?> _values = new();

        public DLMSMeter(
            string meterNo,
            string logicalName,
            int clientAddress,
            int serverAddress
            //byte[]? masterKey = null,
            //byte[]? authenticationKey = null,
            //byte[]? blockCipherKey = null
            //byte[]? hlsUsKey = null,
            //byte[]? hlsFwKey = null
            )
        {
            MeterNo = meterNo;
            LogicalName = logicalName;
            ClientAddress = clientAddress;
            ServerAddress = serverAddress;
            //MasterKey = masterKey;
            //AuthenticationKey = authenticationKey;
            //BlockCipherKey = blockCipherKey;
            //HlsUsKey = hlsUsKey;
            //HlsFwKey = hlsFwKey;
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
