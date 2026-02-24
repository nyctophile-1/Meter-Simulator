using System;
using System.Collections.Generic;
using System.Text;

namespace MeterSimulator.Config
{
    public class MeterConfig
    {
        public int MeterCount { get; set; } = 150;
        public int BasePort { get; set; } = 4059;
        public int ClientAddress { get; set; } = 16;
        public int ServerAddressStart { get; set; } = 1;
        public string LogicalName { get; set; } = "1.0.0.0.0.255";
    }
}
