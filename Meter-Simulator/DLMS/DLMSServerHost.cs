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
            Ciphering.Security = Security.AuthenticationEncryption;
            Ciphering.SystemTitle = meter.SystemTitle;
            Ciphering.BlockCipherKey = meter.BlockCipherKey;
            Ciphering.AuthenticationKey = meter.AuthenticationKey;
            Settings.UseLogicalNameReferencing = true;
            _meter = meter;

            // ---- DLMS addressing ----
            //ServerAddress = meter.ServerAddress;
            //ClientAddress = meter.ClientAddress;

            // ---- Authentication (v1 = NONE / LLS) ----
            Settings.Authentication = Authentication.High;
            // ---- Network (TCP Wrapper) ----
            _network = new GXNet(NetworkType.Tcp, port)
            {
                Trace = TraceLevel.Verbose
            };

            Settings.MaxPduSize = 65535;

            Items.Clear();

            InitializeObjects();        // create .3
            InitializeSecuritySetup();  // create 43.0.0.255
            InitializeAssociation();    // build BOTH associations from _objects

            Items.AddRange(_objects);   // add everything at the very end


            Console.WriteLine("Items list:");
            foreach (var obj in Items)
            {
                Console.WriteLine(obj.LogicalName);
            }
            //Console.WriteLine("All objects in _objects:");
            //foreach (var o in _objects)
            //{
            //    Console.WriteLine(o.LogicalName);
            //}
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
                ClientSAP = 10  // ADD THIS - match client address
            };
            // ... rest of public assoc code

            publicAssoc.ObjectList.AddRange(_objects);
            publicAssoc.ObjectList.Add(publicAssoc);
            _objects.Add(publicAssoc);

            // SET ACCESS FOR PUBLIC ASSOCIATION
            var icPublic = publicAssoc.ObjectList.FindByLN(ObjectType.Data, "0.0.43.1.3.255");
            if (icPublic != null)
            {
                icPublic.SetAccess(2, AccessMode.Read);
            }

            //Console.WriteLine($"Public Assoc ObjectList count: {publicAssoc.ObjectList.Count}");
            //foreach (var obj in publicAssoc.ObjectList)
            //{
            //    Console.WriteLine($"  {obj.ObjectType} - {obj.LogicalName}");
            //}
            // HIGH Association
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
                ClientSAP = 30  // ADD THIS
            };
            association.SecuritySetupReference = "0.0.43.0.0.255";
            var icInObjects = _objects.FirstOrDefault(o => o.LogicalName == "0.0.43.1.3.255");
            //Console.WriteLine($"IC in _objects: {icInObjects != null}");
            association.ObjectList.AddRange(_objects.ToArray());
            association.ObjectList.Add(association);
            _objects.Add(association);
            //Console.WriteLine("HIGH Assoc ObjectList:");
            //foreach (var obj in association.ObjectList)
            //{
            //    Console.WriteLine($"  {obj.ObjectType} - {obj.LogicalName}");
            //}

            // SET ACCESS FOR HIGH ASSOCIATION
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
                // Pass incoming bytes to DLMS server
                var data = (byte[])e.Data;
                //Console.WriteLine($"Received {data.Length} bytes");
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

                // Special handling for Association object_list
                if (arg.Target is GXDLMSAssociationLogicalName && arg.Index == 2)
                {
                    //Console.WriteLine($"  Reading association object_list!");
                    var assoc = arg.Target as GXDLMSAssociationLogicalName;
                    //Console.WriteLine($"  ObjectList count: {assoc.ObjectList.Count}");
                    //foreach (var obj in assoc.ObjectList)
                    //{
                    //    Console.WriteLine($"    {obj.LogicalName}");
                    //}
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
                    //Console.WriteLine($"  GetValue returned: {value}");

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
            Console.WriteLine($"FindObject: Type={objectType}, LN={ln}");

            if (!string.IsNullOrEmpty(ln))
            {
                var obj = _objects.FirstOrDefault(o =>
                    o.LogicalName == ln &&
                    o.ObjectType == objectType);
                //Console.WriteLine($"  Found: {obj != null}");
                //if (obj is GXDLMSAssociationLogicalName aln)
                //{
                //    Console.WriteLine($"  Association Context: {aln.ApplicationContextName.ContextId}");
                //}
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

            if (arg.Target is GXDLMSAssociationLogicalName && arg.Index == 2)
                return AccessMode.Read;

            if (arg.Target is GXDLMSData && arg.Index == 2)
                return AccessMode.ReadWrite; 
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

            var assoc1 = Items.FindByLN(ObjectType.AssociationLogicalName, "0.0.40.0.1.255");
            var assoc2 = Items.FindByLN(ObjectType.AssociationLogicalName, "0.0.40.0.0.255");

            //Console.WriteLine($"Public Assoc (0.0.40.0.1.255): {assoc1 != null}");

            //Console.WriteLine($"High Assoc (0.0.40.0.0.255): {assoc2 != null}");
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
            //foreach (var arg in args)
            //    arg.Error = ErrorCode.ReadWriteDenied;
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
