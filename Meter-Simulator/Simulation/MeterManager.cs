using MeterSimulator.Config;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace MeterSimulator.Simulation
{
    public class MeterManager
    {
        private readonly MeterConfig _config;
        private readonly List<DLMSServerHost> _servers = new();

        public MeterManager(MeterConfig config)
        {
            _config = config;
        }

        public void Initialize()
        {
            for (int i = 0; i < _config.MeterCount; i++)
            {
                var meter = new DLMSMeter(
                    meterNo: $"MTR{i + 1:D5}",
                    logicalName: _config.LogicalName,
                    clientAddress: _config.ClientAddress,
                    serverAddress: _config.ServerAddressStart + i
                );

                int port = _config.BasePort + i;

                var server = new DLMSServerHost(meter, port);
                _servers.Add(server);
            }
        }

        public void StartAll()
        {
            foreach (var server in _servers)
            {
                server.Start();
            }

            Console.WriteLine($"Started {_servers.Count} meters.");
        }

        public void StopAll()
        {
            foreach (var server in _servers)
            {
                server.Stop();
            }

            Console.WriteLine("All meters stopped.");
        }
    }
}
