using Gurux.DLMS;
using MeterSimulator.Config;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Text;

namespace MeterSimulator.Simulation
{
    public class MeterManager
    {
        private readonly MeterConfig _config;
        //private readonly List<DLMSServerHost> _servers = new();
        private DLMSServerSession _server;
        private DLMSTCPGateway _gateway;
        private Dictionary<int, DLMSMeter> _meters = new();

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

                _meters[meter.ServerAddress] = meter;
                Console.WriteLine($"Initialized meter: {meter.MeterNo} with Server Address: {meter.ServerAddress}");
                //int port = _config.BasePort + i;
                //var server = new DLMSServerHost(meter, port);
                //_servers.Add(server);
            }
            _gateway = new DLMSTCPGateway(_meters, _config.BasePort);
            //_server = new DLMSServerHost(_meters, _config.BasePort);
        }

        public void StartAll()
        {
            _gateway.Start();

            Console.WriteLine($"Started {_config.MeterCount} meters.");
        }

        public void StopAll()
        {
            _gateway.Stop();
            Console.WriteLine("All meters stopped.");
        }
    }
}
