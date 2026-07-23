using Gurux.Common;
using Gurux.Net;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace MeterSimulator.DLMS
{
    public class DLMSTCPGateway
    {
        // serverAddress → pre-built, already-Initialized session.  Sessions are
        // created eagerly in MeterManager (loaded from XML at startup), so the
        // gateway only routes incoming bytes to the right meter's session.
        private readonly Dictionary<int, DLMSServerSession> _sessions;
        private readonly GXNet _network;

        public DLMSTCPGateway(Dictionary<int, DLMSServerSession> sessions, int port)
        {
            _sessions = sessions;
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

                // Route to the meter's pre-built session (loaded from XML at startup).
                if (!_sessions.TryGetValue(serverAddress, out var session))
                {
                    Console.WriteLine($"Meter not found: {serverAddress}");
                    return;
                }

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
            // Persistent sessions are NOT torn down on disconnect — a meter outlives
            // any single HES connection.  Gurux resets the session's connection state
            // automatically on the next SNRM/AARQ, so the same instance serves the
            // next client cleanly.
            Console.WriteLine($"Client disconnected: {e.Info}");
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
