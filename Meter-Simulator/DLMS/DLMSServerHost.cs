using Gurux.Common;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Objects.Enums;
using Gurux.DLMS.Secure;
using Gurux.Net;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace MeterSimulator.DLMS
{
    public class DLMSServerHost : GXDLMSSecureServer
    {
        private readonly DLMSMeter _meter;
        private readonly GXNet _network;
        private readonly GXDLMSObjectCollection _objects = new();
        public DLMSServerHost(DLMSMeter meter, int port)
        : base(
            true, // useLogicalNameReferencing
            InterfaceType.WRAPPER)
        {
            _meter = meter;

            // ---- DLMS addressing ----
            //ServerAddress = meter.ServerAddress;
            //ClientAddress = meter.ClientAddress;

            // ---- Authentication (v1 = NONE / LLS) ----
            Settings.Authentication = Authentication.HighGMAC;
            // ---- Network (TCP Wrapper) ----
            _network = new GXNet(NetworkType.Tcp, port)
            {
                Trace = TraceLevel.Verbose
            };

            Ciphering.Security = Security.AuthenticationEncryption;
            Ciphering.SystemTitle = _meter.SystemTitle;
            Ciphering.BlockCipherKey = _meter.BlockCipherKey;
            Ciphering.AuthenticationKey = _meter.AuthenticationKey;

            InitializeObjects();
            InitializeSecuritySetup();
            InitializeAssociation();
        }

        private void OnDataReceived(object? sender, ReceiveEventArgs e)
        {
            try
            {
                // Pass incoming bytes to DLMS server
                var data = (byte[])e.Data;
                byte[] reply = HandleRequest(data);

                if (reply.Length != 0)
                {
                    _network.Send(reply, e.SenderInfo);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DLMS error: {ex.Message}");
            }
        }

        private void InitializeObjects()
        {
            // Example: Active Energy Import (1.0.1.8.0.255)
            var energy = new GXDLMSRegister
            {
                LogicalName = "1.0.1.8.0.255",
                Scaler = 0,
                Unit = Unit.None,
                Value = 1
            };

            var clock = new GXDLMSClock
            {
                LogicalName = "0.0.1.0.0.255",
                Time = DateTime.Now,
                Status = ClockStatus.Ok
            };

            _objects.Add(energy);
            _objects.Add(clock);
            _objects.Add(new GXDLMSData("0.0.43.1.0.255")
            {
                Value = 1u
            });
        }

        protected override void PreRead(ValueEventArgs[] args)
        {
            foreach (var arg in args)
            {
                if (arg.Target is GXDLMSRegister obj)
                {
                    var obis = obj.LogicalName;
                    var value = _meter.GetValue(obis);

                    if (value != null)
                    {
                        arg.Value = value;
                        arg.Handled = true;
                    }
                }
            }
        }
        public void Start()
        {
            Initialize(true);
            _network.OnReceived += OnDataReceived;
            _network.Open();
            Console.WriteLine($"DLMS Meter {_meter.MeterNo} listening on port {_network.Port}");
        }
        private void InitializeAssociation()
        {
            var association = new GXDLMSAssociationLogicalName
            {
                LogicalName = "0.0.40.0.0.255",
                Version = 2,
                ApplicationContextName = new GXApplicationContextName
                {
                    ContextId = Gurux.DLMS.Objects.Enums.ApplicationContextName.LogicalNameWithCiphering
                },
                AuthenticationMechanismName = new GXAuthenticationMechanismName
                {
                    MechanismId = Authentication.HighGMAC
                }
                //Secret = Encoding.ASCII.GetBytes("12345678")
            };

            association.SecuritySetupReference = "0.0.43.0.0.255";

            association.ObjectList.AddRange(_objects.ToArray());
            association.ObjectList.Add(association);

            // Register association with server
            _objects.Add(association);
        }

        public void Stop()
        {
            _network.Close();
        }

        protected override GXDLMSObject FindObject(
            ObjectType objectType,
            int sn,
            string ln)
        {
            // Logical Name referencing
            if (!string.IsNullOrEmpty(ln))
            {
                return _objects.FirstOrDefault(o =>
                    o.LogicalName == ln &&
                    o.ObjectType == objectType);
            }

            // Short Name referencing (not used)
            if (sn != 0)
            {
                return _objects.FirstOrDefault(o => o.ShortName == sn);
            }

            return null;
        }

        private void InitializeSecuritySetup()
        {
            var securitySetup = new GXDLMSSecuritySetup
            {
                LogicalName = "0.0.43.0.0.255",
                Version = 2,
                SecurityPolicy = SecurityPolicy.AuthenticatedEncrypted,
                SecuritySuite = SecuritySuite.Suite0,
               
                ServerSystemTitle = _meter.SystemTitle,
                Guek = _meter.BlockCipherKey,
                Gak = _meter.AuthenticationKey
            };

            _objects.Add(securitySetup);
        }

        protected override bool IsTarget(int serverAddress, int clientAddress)
        {
            // For TCP Wrapper + single meter simulator,
            // always accept the connection
            return true;
        }


        protected override AccessMode GetAttributeAccess(ValueEventArgs arg)
        {
            if (arg.Target is GXDLMSRegister && arg.Index == 2)
        return AccessMode.Read;

    // Clock: allow reading Time (attribute 2)
    if (arg.Target is GXDLMSClock && arg.Index == 2)
        return AccessMode.Read;

    // Association: allow reading object list (attribute 2)
    if (arg.Target is GXDLMSAssociationLogicalName && arg.Index == 2)
        return AccessMode.Read;

    // Everything else: no access
    return AccessMode.NoAccess;
        }

        protected override AccessMode3 GetAttributeAccess3(ValueEventArgs arg)
        {
            return AccessMode3.Read;
        }

        protected override MethodAccessMode GetMethodAccess(ValueEventArgs arg)
        {
            return MethodAccessMode.Access;
        }

        protected override MethodAccessMode3 GetMethodAccess3(ValueEventArgs arg)
        {
            return MethodAccessMode3.Access;
        }

        protected override SourceDiagnostic ValidateAuthentication(
            Authentication authentication,
            byte[] password)
        {
            // We only support Authentication.None for now
            if (authentication == Authentication.None)
            {
                return SourceDiagnostic.None; // ACCEPT
            }
            if (password != null &&
            password.SequenceEqual(Encoding.ASCII.GetBytes(_meter.LlsPassword)))
            {
                return SourceDiagnostic.None; // ACCEPT
            }
            if (authentication == Authentication.HighGMAC)
            {
                return SourceDiagnostic.None; // ACCEPT
            }
            // Reject everything else
            return SourceDiagnostic.AuthenticationFailure;
        }

        protected override void Connected(GXDLMSConnectionEventArgs connectionInfo)
        {
            Console.WriteLine(
                $"DLMS client connected");
        }

        protected override void InvalidConnection(GXDLMSConnectionEventArgs connectionInfo)
        {
            //throw new NotImplementedException();
        }

        protected override void Disconnected(GXDLMSConnectionEventArgs connectionInfo)
        {
            Console.WriteLine(
                $"DLMS client Disconnected");
        }

        public override void PreGet(ValueEventArgs[] args)
        {
            //throw new NotImplementedException();
        }

        public override void PostGet(ValueEventArgs[] args)
        {
            //throw new NotImplementedException();
        }

        protected override void PreWrite(ValueEventArgs[] args)
        {
            foreach (var arg in args)
                arg.Error = ErrorCode.ReadWriteDenied;
        }

        protected override void PreAction(ValueEventArgs[] args)
        {
            foreach (var arg in args)
                arg.Error = ErrorCode.ReadWriteDenied;
        }

        protected override void PostRead(ValueEventArgs[] args)
        {
            //throw new NotImplementedException();
        }

        protected override void PostWrite(ValueEventArgs[] args)
        {
            //throw new NotImplementedException();
        }

        protected override void PostAction(ValueEventArgs[] args)
        {
            //throw new NotImplementedException();
        }

        protected override void Execute(List<KeyValuePair<GXDLMSObject, int>> actions)
        {
            //throw new NotImplementedException();
        }
    }
}
