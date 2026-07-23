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
        private readonly List<DLMSServerSession> _sessions = new();

        public MeterManager(MeterConfig config)
        {
            _config = config;
        }

        public void Initialize()
        {
            _meters.Clear();
            _gateways.Clear();
            _sessions.Clear();

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

                // Build the meter's DLMS object model from XML NOW, before any HES
                // request arrives.  The session (XML load + object build + association
                // setup) used to be created lazily on first byte received; doing it
                // here means every meter is fully live at startup and independent of
                // any client connection — the foundation the push service needs.
                var session = new DLMSServerSession(meter, _config.Push);
                session.Initialize(true);
                _sessions.Add(session);

                var sessionMap = new Dictionary<int, DLMSServerSession>
                {
                    [meter.ServerAddress] = session
                };

                var gateway = new DLMSTCPGateway(sessionMap, port);
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

            // Meters are fully loaded and listening — now start their push timers.
            foreach (var session in _sessions)
            {
                session.StartPush();
            }

            Console.WriteLine(
                $"Started {_config.MeterCount} meters on ports {_config.BasePort} to {_config.BasePort + _config.MeterCount - 1}.");
        }

        public void StopAll()
        {
            foreach (var session in _sessions)
            {
                session.StopPush();
            }

            foreach (var gateway in _gateways)
            {
                gateway.Stop();
            }

            Console.WriteLine("All meters stopped.");
        }
    }
}
