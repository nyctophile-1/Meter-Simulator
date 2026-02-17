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
            true,
            InterfaceType.WRAPPER)
        {
            Ciphering.Security = Security.AuthenticationEncryption;
            Ciphering.SystemTitle = meter.SystemTitle;
            Ciphering.BlockCipherKey = meter.BlockCipherKey;
            Ciphering.AuthenticationKey = meter.AuthenticationKey;
            Settings.UseLogicalNameReferencing = true;
            _meter = meter;

            Settings.Authentication = Authentication.High;
            _network = new GXNet(NetworkType.Tcp, port)
            {
                Trace = TraceLevel.Verbose
            };

            Settings.MaxPduSize = 65535;

            Items.Clear();

            InitializeObjects();        
            InitializeSecuritySetup();  
            InitializeAssociation(); 
            Items.AddRange(_objects); 

        }

        private void InitializeObjects()
        {
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

            var invocationCounter = new GXDLMSData
            {
                LogicalName = "0.0.43.1.3.255",
                Value = Convert.ToUInt32(1)
            };
            invocationCounter.SetAccess(1, AccessMode.Read);
            invocationCounter.SetAccess(2, AccessMode.ReadWrite);

            _objects.Add(energy);
            _objects.Add(clock);
            _objects.Add(invocationCounter);

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
        private void InitializeAssociation()
        {
            // PUBLIC Association
            var publicAssoc = new GXDLMSAssociationLogicalName
            {
                LogicalName = "0.0.40.0.1.255",
                Version = 2,
                AuthenticationMechanismName = new GXAuthenticationMechanismName
                {
                    MechanismId = Authentication.None
                },
                ApplicationContextName = new GXApplicationContextName
                {
                    ContextId = ApplicationContextName.LogicalName
                },
                ClientSAP = 10 
            };
            publicAssoc.XDLMSContextInfo.Conformance =
                Conformance.GeneralProtection |
                Conformance.GeneralBlockTransfer |
                Conformance.BlockTransferWithGetOrRead |
                Conformance.BlockTransferWithSetOrWrite |
                Conformance.BlockTransferWithAction |
                Conformance.MultipleReferences |
                Conformance.Access |
                Conformance.Get |
                Conformance.Set |
                Conformance.SelectiveAccess |
                Conformance.Action |
                Conformance.DeltaValueEncoding;

            publicAssoc.XDLMSContextInfo.MaxReceivePduSize = 0xFFFF;
            publicAssoc.ObjectList.AddRange(_objects);
            publicAssoc.ObjectList.Add(publicAssoc);
            _objects.Add(publicAssoc);

            var icPublic = publicAssoc.ObjectList.FindByLN(ObjectType.Data, "0.0.43.1.3.255");
            if (icPublic != null)
            {
                icPublic.SetAccess(2, AccessMode.Read);
            }

            var association = new GXDLMSAssociationLogicalName
            {
                LogicalName = "0.0.40.0.0.255",
                Version = 2,
                AuthenticationMechanismName = new GXAuthenticationMechanismName
                {
                    MechanismId = Authentication.High
                },
                ApplicationContextName = new GXApplicationContextName
                {
                    ContextId = ApplicationContextName.LogicalName
                },
                Secret = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA"),
                ClientSAP = 30
            };

            association.XDLMSContextInfo.Conformance =
                Conformance.GeneralProtection |
                Conformance.GeneralBlockTransfer |
                Conformance.BlockTransferWithGetOrRead |
                Conformance.BlockTransferWithSetOrWrite |
                Conformance.BlockTransferWithAction |
                Conformance.MultipleReferences |
                Conformance.Access |
                Conformance.Get |
                Conformance.Set |
                Conformance.SelectiveAccess |
                Conformance.Action |
                Conformance.DeltaValueEncoding;

            association.XDLMSContextInfo.MaxReceivePduSize = 0xFFFF;

            association.SecuritySetupReference = "0.0.43.0.0.255";
            var icInObjects = _objects.FirstOrDefault(o => o.LogicalName == "0.0.43.1.3.255");
            association.ObjectList.AddRange(_objects.ToArray());
            association.ObjectList.Add(association);
            _objects.Add(association);

            var ic = association.ObjectList.FindByLN(ObjectType.Data, "0.0.43.1.3.255");
            if (ic != null)
            {
                ic.SetAccess(2, AccessMode.ReadWrite);
            }
        }
        private void OnDataReceived(object? sender, ReceiveEventArgs e)
        {
            try
            {
                var data = (byte[])e.Data;

                Console.WriteLine($"Hex Received: {BitConverter.ToString(data)}");

                byte[] reply = HandleRequest(data);
                if (reply.Length != 0)
                {
                    Console.WriteLine($"Sending reply: {BitConverter.ToString(reply)}");
                    _network.Send(reply, e.SenderInfo);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DLMS error: {ex.Message}");
                Console.WriteLine($"Stack: {ex.StackTrace}");  // ← Add this
            }
        }

        protected override void PreRead(ValueEventArgs[] args)
        {
            foreach (var arg in args)
            {
                Console.WriteLine($"PreRead: {arg.Target.ObjectType} - {arg.Target.LogicalName}, Attr={arg.Index}");

                if (arg.Target is GXDLMSAssociationLogicalName && arg.Index == 2)
                {
                    var assoc = arg.Target as GXDLMSAssociationLogicalName;
                }

                if (arg.Target.LogicalName == "0.0.43.1.3.255" && arg.Index == 2)
                {
                    var ic0 = Items.FindByLN(ObjectType.Data, "0.0.43.1.0.255") as GXDLMSData;

                    if (ic0 != null)
                    {
                        arg.Value = ic0.Value;
                        arg.Handled = true;
                    }
                }


                var obis = arg.Target.LogicalName;

                if (arg.Target is GXDLMSRegister || arg.Target is GXDLMSData)
                {
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
        

        public void Stop()
        {
            _network.Close();
        }

        protected override GXDLMSObject FindObject(ObjectType objectType, int sn, string ln)
        {
            if (!string.IsNullOrEmpty(ln))
            {
                var obj = _objects.FirstOrDefault(o =>
                    o.LogicalName == ln &&
                    o.ObjectType == objectType);
                
                return obj;
            }

            if (sn != 0)
            {
                return _objects.FirstOrDefault(o => o.ShortName == sn);
            }

            return null;
        }



        protected override bool IsTarget(int serverAddress, int clientAddress)
        {
            return true;
        }


        protected override AccessMode GetAttributeAccess(ValueEventArgs arg)
        {
            if (arg.Target is GXDLMSRegister && arg.Index == 2)
                return AccessMode.Read;

            if (arg.Target is GXDLMSClock && arg.Index == 2)
                return AccessMode.Read;

            if (arg.Target is GXDLMSAssociationLogicalName && arg.Index == 2)
                return AccessMode.Read;

            if (arg.Target is GXDLMSData && arg.Index == 2)
                return AccessMode.ReadWrite; 

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
            if (authentication == Authentication.None)
            {
                return SourceDiagnostic.None; // ACCEPT
            }
            if (password != null &&
            password.SequenceEqual(Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA")))
            {
                return SourceDiagnostic.None; // ACCEPT
            }
            if (authentication == Authentication.High)
            {
                return SourceDiagnostic.None; // ACCEPT
            }

            return SourceDiagnostic.AuthenticationFailure;
        }

        protected override void Connected(GXDLMSConnectionEventArgs e)
        {
            Console.WriteLine($"Client connected");
        }

        protected override void Disconnected(GXDLMSConnectionEventArgs connectionInfo)
        {
            Console.WriteLine( $"DLMS client Disconnected");
        }

        protected override void PreWrite(ValueEventArgs[] args)
        {
            foreach(var arg in args)
            {
                if (arg.Target.LogicalName == "0.0.43.1.3.255" && arg.Index == 2)
                {
                    var ic0 = Items.FindByLN(ObjectType.Data, "0.0.43.1.0.255") as GXDLMSData;

                    if (ic0 != null)
                    {
                        ic0.Value = arg.Value;
                        arg.Handled = true;
                    }
                }
            }
        }

        protected override void PreAction(ValueEventArgs[] args)
        {
        }

        protected override void PostRead(ValueEventArgs[] args)
        {
        }

        protected override void PostWrite(ValueEventArgs[] args)
        {
        }

        protected override void PostAction(ValueEventArgs[] args)
        {
        }

        protected override void Execute(List<KeyValuePair<GXDLMSObject, int>> actions)
        {
        }

        public override void PreGet(ValueEventArgs[] args)
        {
        }

        public override void PostGet(ValueEventArgs[] args)
        {
        }
        protected override void InvalidConnection(GXDLMSConnectionEventArgs connectionInfo)
        {
        }
    }
}
