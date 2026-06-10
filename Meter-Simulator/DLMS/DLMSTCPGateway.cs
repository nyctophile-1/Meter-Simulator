using Gurux.Common;
using Gurux.Net;
using MeterSimulator.Models;
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;

namespace MeterSimulator.DLMS
{
    public class DLMSTCPGateway
    {
        private readonly Dictionary<int, DLMSMeter> _meters;
        private readonly GXNet _network;
        private readonly ConcurrentDictionary<string, DLMSServerSession> _sessions =
            new ConcurrentDictionary<string, DLMSServerSession>();

        public DLMSTCPGateway(Dictionary<int, DLMSMeter> meters, int port)
        {
            _meters = meters;
            _network = new GXNet(NetworkType.Tcp, port);
            _network.OnReceived += OnDataReceived;
            _network.OnClientDisconnected += OnClientDisconnected;
        }

        private void OnDataReceived(object sender, ReceiveEventArgs e)
        {
            try
            {
                var data = (byte[])e.Data;

                if (data.Length < 8)
                    return;

                Console.WriteLine($"Hex Received: {BitConverter.ToString(data)}");

                // WRAPPER header → ServerAddress at offset 4 (Big Endian)
                ushort serverAddress =
                    BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(4));

                if (!_meters.TryGetValue(serverAddress, out var meter))
                {
                    Console.WriteLine($"Meter not found: {serverAddress}");
                    return;
                }

                // Get or create session
                string clientKey = e.SenderInfo.ToString();
                string sessionKey = $"{clientKey}_{serverAddress}";

                var session = _sessions.GetOrAdd(sessionKey, key =>
                {
                    var s = new DLMSServerSession(meter);
                    s.Initialize(true);
                    return s;
                });

                byte[] reply = session.HandleRequest(data);
                Console.WriteLine($"HandleRequest reply: {(reply == null ? "NULL" : reply.Length + " bytes")}");

                if (reply != null && reply.Length > 0)
                {
                    //Thread.Sleep(200);
                    Console.WriteLine($"Sending reply: {BitConverter.ToString(reply)}");
                    _network.Send(reply, e.SenderInfo);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DLMS error: {ex}");
            }
        }

        private void OnClientDisconnected(object sender, ConnectionEventArgs e)
        {
            if (_sessions.TryRemove(e.Info, out var session))
            {
                Console.WriteLine($"Session removed: {e.Info}");
            }
        }

        public void Start()
        {
            Console.WriteLine("DLMS TCP Gateway started...");
            _network.Open();
        }

        public void Stop()
        {
            // Clear all active sessions
            _sessions.Clear();

            // Close network listener
            _network.Close();

            Console.WriteLine("DLMS TCP Gateway stopped.");
        }
    }
}
