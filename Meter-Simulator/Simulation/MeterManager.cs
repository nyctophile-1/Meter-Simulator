using MeterSimulator.Config;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using System;
using System.Collections.Generic;

namespace MeterSimulator.Simulation
{
    public class MeterManager
    {
        private readonly MeterConfig _config;
        private readonly List<DLMSTCPGateway> _gateways = new();
        private readonly Dictionary<int, DLMSMeter> _meters = new();

        public MeterManager(MeterConfig config)
        {
            _config = config;
        }

        public void Initialize()
        {
            _meters.Clear();
            _gateways.Clear();

            for (int i = 0; i < _config.MeterCount; i++)
            {
                // Server address can stay the same (typically 1) because each meter is isolated by TCP port.
                int serverAddress = _config.ServerAddressStart;
                int port = _config.BasePort + i;

                var meter = new DLMSMeter(
                    meterNo: $"MTR{i + 1:D5}",
                    logicalName: _config.LogicalName,
                    clientAddress: _config.ClientAddress,
                    serverAddress: serverAddress
                );

                _meters[meter.ServerAddress] = meter;

                var meterMap = new Dictionary<int, DLMSMeter>
                {
                    [meter.ServerAddress] = meter
                };

                var gateway = new DLMSTCPGateway(meterMap, port);
                _gateways.Add(gateway);

                Console.WriteLine(
                    $"Initialized meter: {meter.MeterNo} | Server Address: {meter.ServerAddress} | Port: {port}");
            }
        }

        public void StartAll()
        {
            foreach (var gateway in _gateways)
            {
                gateway.Start();
            }

            Console.WriteLine(
                $"Started {_config.MeterCount} meters on ports {_config.BasePort} to {_config.BasePort + _config.MeterCount - 1}.");
        }

        public void StopAll()
        {
            foreach (var gateway in _gateways)
            {
                gateway.Stop();
            }

            Console.WriteLine("All meters stopped.");
        }
    }
}
