using Gurux.Common;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Objects.Enums;
using Gurux.DLMS.Secure;
using Gurux.Net;
using MeterSimulator.Config;
using MeterSimulator.Diagnostics;
using MeterSimulator.Models;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MeterSimulator.DLMS
{
    public class DLMSServerSession : GXDLMSSecureServer
    {
        private readonly DLMSMeter _meter;
        //private readonly GXNet _network;
        private readonly GXDLMSObjectCollection _objects = new();
        private readonly GXDLMSObjectCollection _objectsFromFile = new();

        // ── Push (outbound DataNotification) ──────────────────────────────────
        // The meter acts as a TCP CLIENT for push: on a timer it builds a
        // DataNotification from each PushSetup's push_object_list and connects out
        // to that object's Destination.  Gurux does NOT transmit push itself, so
        // the encoder (_notify), the timer, and the socket are ours.
        private readonly PushConfig? _pushConfig;
        private readonly GXDLMSSecureNotify _notify;
        private readonly object _pushLock = new();
        private Timer? _pushTimer;

        public DLMSServerSession(DLMSMeter meter, string templatePath, PushConfig? pushConfig = null)
        : base(
            true,
            InterfaceType.WRAPPER)
        {
            if (string.IsNullOrWhiteSpace(templatePath))
                throw new ArgumentException("A meter template (XML) path is required.", nameof(templatePath));
            // Enable server-side ciphering so the meter supports the ciphered LN association
            // (application-context LN_WITH_CIPHERING) that a secured HES/GXDLMSDirector uses.
            // Without this the server downgrades to plain LN and permanently rejects the AARQ.
            Ciphering.Security = Security.AuthenticationEncryption;
            Ciphering.SystemTitle = meter.SystemTitle;
            Ciphering.BlockCipherKey = meter.BlockCipherKey;
            Ciphering.AuthenticationKey = meter.AuthenticationKey;
            Settings.UseLogicalNameReferencing = true;
            _meter = meter;
            _pushConfig = pushConfig;

            // Encoder for outbound DataNotification frames.  Meter is the source
            // (server address); the client/HES is the destination address.
            _notify = new GXDLMSSecureNotify(
                true, meter.ClientAddress, meter.ServerAddress, InterfaceType.WRAPPER);

            Settings.Authentication = Authentication.High;
            //_network = new GXNet(NetworkType.Tcp, port)
            //{
            //    Trace = TraceLevel.Verbose
            //};

            Settings.MaxPduSize = 65535;

            Items.Clear();

            // Template (DLMS object model) is chosen per-batch and resolved to a path by
            // the host (MeterSessionManager) — no hardcoded/machine-specific path here.
            var loader = new MeterObjectLoader(templatePath);

            loader.Load(_objectsFromFile);

            // The XML template bakes in a push Destination (often a real head-end
            // address). If a Destination override is configured, rewrite it on every
            // PushSetup NOW — before the objects are registered in Items — so both
            // the push sender and the value the HES reads back reflect our target.
            ApplyPushDestinationOverride(_objectsFromFile);

            // The XML template bakes in a single serial (e.g. "SA1231166").  Every meter is
            // built from a SHARED template, so rewrite the serial-number object to THIS meter's
            // own serial before the values are copied into the meter store — otherwise every
            // meter would report the template's serial and HES couldn't tell them apart
            // (HES reconciles IP-vs-meterno using the serial in the DLMS payload).
            ApplySerialOverride(_objectsFromFile);

            foreach (var obj in _objectsFromFile)
            {
                if (obj is GXDLMSRegister reg)
                {
                    _meter.SetValue(reg.LogicalName, reg.Value);
                }
                else if (obj is GXDLMSData data)
                {
                    _meter.SetValue(data.LogicalName, data.Value);
                }
            }

            //InitializeObjects();
            InitializeSecuritySetup();
            InitializeAssociation();

            var publicAssoc = _objects.FirstOrDefault(o => o.LogicalName == "0.0.40.0.1.255") as GXDLMSAssociationLogicalName;
            var association = _objects.FirstOrDefault(o => o.LogicalName == "0.0.40.0.0.255") as GXDLMSAssociationLogicalName;

            foreach (var obj in _objects)
            {
                CoreLog.Debug($"Added object: {obj.ObjectType} - {obj.LogicalName}");
                Items.Add(obj);
            }

            // MeterObjectLoader.Load() already deduplicates by (ObjectType, LN) and
            // rewires every profile's CaptureObjects to point at the canonical instances
            // within that same collection.  The only "duplicates" we'll see here are
            // association objects (0.0.40.0.x.255) that InitializeAssociation already
            // added to _objects — everything else should land in the `else` branch.
            foreach (var obj in _objectsFromFile)
            {
                var existing = Items.FirstOrDefault(x =>
                    x.LogicalName == obj.LogicalName && x.ObjectType == obj.ObjectType);

                if (existing != null)
                {
                    // Already registered (e.g. associations created by InitializeAssociation).
                    // Nothing to sync — the loader has already seeded the incoming object.
                    CoreLog.Debug($"[Session] Skipping duplicate: {obj.ObjectType} {obj.LogicalName}");
                }
                else
                {
                    Items.Add(obj);
                    _objects.Add(obj);
                    publicAssoc?.ObjectList.Add(obj);
                    association?.ObjectList.Add(obj);
                    if(obj.LogicalName == "0.0.25.9.0.255")
                    {
                        CoreLog.Debug($"PUSHHHHHHH [Session] Registered: {obj.ObjectType} {obj.LogicalName}");
                    }
                    CoreLog.Debug($"[Session] Registered: {obj.ObjectType} {obj.LogicalName}");
                }
            }

            // Safety net: if any CaptureObject key somehow still points to an instance
            // not in Items, re-wire it now.  With a clean load this is a no-op.
            RewireProfileCaptureObjects();
        }

        #region Push (outbound DataNotification)

        /// <summary>
        /// Replaces the Destination on every PushSetup with the configured override
        /// (if any).  No-op when the override is empty — the XML value is kept.
        /// </summary>
        private void ApplyPushDestinationOverride(GXDLMSObjectCollection objects)
        {
            var dest = _pushConfig?.Destination;
            if (string.IsNullOrWhiteSpace(dest))
                return;

            foreach (var push in objects.OfType<GXDLMSPushSetup>())
            {
                CoreLog.Debug(
                    $"[Push] {_meter.MeterNo}: rewriting Destination on {push.LogicalName} " +
                    $"'{push.Destination}' → '{dest}'");
                push.Destination = dest;
            }
        }

        /// <summary>
        /// OBIS of the meter serial number (a GXDLMSData string, attr 2).
        /// </summary>
        private const string SerialNumberLN = "0.0.96.1.0.255";

        /// <summary>
        /// Replaces the serial-number object's value with this meter's own serial
        /// (<see cref="DLMSMeter.MeterNo"/>, "MY" + 9-digit index).  No-op if the template
        /// has no serial object.
        /// </summary>
        private void ApplySerialOverride(GXDLMSObjectCollection objects)
        {
            if (objects.FindByLN(ObjectType.Data, SerialNumberLN) is not GXDLMSData serial)
            {
                CoreLog.Debug($"[Serial] {_meter.MeterNo}: no {SerialNumberLN} in template, skipping");
                return;
            }

            CoreLog.Debug(
                $"[Serial] {_meter.MeterNo}: rewriting {SerialNumberLN} '{serial.Value}' → '{_meter.MeterNo}'");
            serial.Value = _meter.MeterNo;
            serial.SetDataType(2, DataType.String);
        }

        /// <summary>
        /// Starts the periodic push timer if enabled in config.  Called by
        /// MeterManager after the meter is fully loaded from XML.
        /// </summary>
        public void StartPush()
        {
            if (_pushConfig == null || !_pushConfig.Enabled)
                return;

            int seconds = Math.Max(1, _pushConfig.IntervalSeconds);
            var period = TimeSpan.FromSeconds(seconds);
            _pushTimer = new Timer(_ => SafeSendPush(), null, period, period);

            CoreLog.Debug(
                $"[Push] {_meter.MeterNo}: enabled — every {seconds}s, " +
                $"ciphering={(_pushConfig.UseCiphering ? "on" : "off")}");
        }

        /// <summary>Stops the push timer.  Called on shutdown.</summary>
        public void StopPush()
        {
            _pushTimer?.Dispose();
            _pushTimer = null;
        }

        private void SafeSendPush()
        {
            try
            {
                SendPush();
            }
            catch (Exception ex)
            {
                CoreLog.Warn($"[Push] {_meter.MeterNo}: unexpected error: {ex.Message}");
            }
        }

        /// <summary>
        /// Builds and sends a DataNotification for every PushSetup that has a
        /// non-empty Destination.  Values are synced from the meter first so the
        /// payload is current; Gurux encodes the frames, we open the socket.
        /// </summary>
        private void SendPush()
        {
            var pushObjects = _objects.OfType<GXDLMSPushSetup>()
                .Where(p => !string.IsNullOrWhiteSpace(p.Destination))
                .ToList();

            if (pushObjects.Count == 0)
            {
                CoreLog.Debug($"[Push] {_meter.MeterNo}: no PushSetup with a Destination, skipping");
                return;
            }

            foreach (var push in pushObjects)                
            {
                if (!TryParseDestination(push.Destination, _pushConfig!.Port,
                        out string host, out int port))
                {
                    CoreLog.Warn($"[Push] {_meter.MeterNo}: bad Destination '{push.Destination}'");
                    continue;
                }

                // Make the push carry live meter values (GeneratePushSetupMessages
                // reads each object's GetValue directly, NOT via the server PreRead).
                SyncPushValues(push);

                ConfigureNotifyCiphering();

                byte[][] frames;
                lock (_pushLock)
                {
                    frames = _notify.GeneratePushSetupMessages(DateTime.UtcNow, push);
                }

                SendFrames(push, host, port, frames);
            }
        }

        /// <summary>
        /// Copies current values from the DLMSMeter onto the objects referenced by
        /// the push_object_list so the outbound payload reflects live data.
        /// </summary>
        private void SyncPushValues(GXDLMSPushSetup push)
        {
            foreach (var kv in push.PushObjectList)
            {
                var obj = kv.Key;
                switch (obj)
                {
                    case GXDLMSRegister reg:
                        var rv = _meter.GetValue(reg.LogicalName);
                        if (rv != null) reg.Value = rv;
                        break;
                    case GXDLMSData data:
                        var dv = _meter.GetValue(data.LogicalName);
                        if (dv != null) data.Value = dv;
                        break;
                    case GXDLMSClock clk:
                        clk.Time = new GXDateTime(DateTime.UtcNow);
                        break;
                }
            }
        }

        /// <summary>Applies plaintext or general-glo-ciphering per config.</summary>
        private void ConfigureNotifyCiphering()
        {
            if (_pushConfig!.UseCiphering)
            {
                _notify.Ciphering.Security = Security.AuthenticationEncryption;
                _notify.Ciphering.SystemTitle = _meter.SystemTitle;
                _notify.Ciphering.BlockCipherKey = _meter.BlockCipherKey;
                _notify.Ciphering.AuthenticationKey = _meter.AuthenticationKey;
            }
            else
            {
                _notify.Ciphering.Security = Security.None;
            }
        }

        /// <summary>
        /// Opens a TCP connection to host:port and writes the frames.  Honors the
        /// PushSetup NumberOfRetries / RepetitionDelay so a missing receiver doesn't
        /// kill the timer.
        /// </summary>
        /// <remarks>
        /// PUSH-READINESS SEAM (merge_task.md #15) — push is currently deferred, but when it is
        /// wired in the merged host this outbound socket MUST bind its LOCAL endpoint to the
        /// meter's own IPv6 (<see cref="DLMSMeter"/> index → address). In the field, push from
        /// meter ABC originates from ABC's IP:4059 — the same IP HES pulls from — so the receiver
        /// correlates the push to the right meter by source IP. The host owns the whole /64 via the
        /// local route, so binding to the meter's address is possible; do it here (e.g.
        /// `new TcpClient(new IPEndPoint(meterAddress, 0))`).
        /// </remarks>
        private void SendFrames(GXDLMSPushSetup push, string host, int port, byte[][] frames)
        {
            int attempts = Math.Max(1, (int)push.NumberOfRetries);

            for (int attempt = 1; attempt <= attempts; attempt++)
            {
                try
                {
                    // NOTE (push-readiness): bind local endpoint to the meter's IPv6 here — see remarks.
                    using var client = new TcpClient();
                    if (!client.ConnectAsync(host, port).Wait(TimeSpan.FromSeconds(5)))
                        throw new TimeoutException("connect timeout");

                    using var stream = client.GetStream();
                    foreach (var frame in frames)
                        stream.Write(frame, 0, frame.Length);
                    stream.Flush();

                    CoreLog.Debug(
                        $"[Push] {_meter.MeterNo}: sent {frames.Length} frame(s) to {host}:{port}");
                    return;
                }
                catch (Exception ex)
                {
                    CoreLog.Debug(
                        $"[Push] {_meter.MeterNo}: attempt {attempt}/{attempts} to " +
                        $"{host}:{port} failed: {ex.Message}");

                    if (attempt < attempts && push.RepetitionDelay > 0)
                        Thread.Sleep(push.RepetitionDelay * 1000);
                }
            }
        }

        /// <summary>
        /// Splits a PushSetup Destination into host + port.
        ///   "127.0.0.1:7000"        → 127.0.0.1 / 7000
        ///   "127.0.0.1"             → 127.0.0.1 / defaultPort
        ///   "[2406:da1a:..]:7000"   → 2406:da1a:.. / 7000   (bracketed IPv6)
        ///   "2406:da1a:.."          → 2406:da1a:.. / defaultPort (bare IPv6)
        /// </summary>
        private static bool TryParseDestination(string dest, int defaultPort,
            out string host, out int port)
        {
            host = string.Empty;
            port = defaultPort;

            if (string.IsNullOrWhiteSpace(dest))
                return false;

            dest = dest.Trim();

            // Bracketed IPv6: [addr] or [addr]:port
            if (dest.StartsWith("["))
            {
                int close = dest.IndexOf(']');
                if (close < 0) return false;
                host = dest.Substring(1, close - 1);
                var rest = dest.Substring(close + 1);
                if (rest.StartsWith(":") && int.TryParse(rest.Substring(1), out int p6))
                    port = p6;
                return host.Length > 0;
            }

            // Exactly one colon → host:port (IPv4 / hostname).
            // Zero colons → bare IPv4/hostname.  More than one → bare IPv6.
            int colons = dest.Count(c => c == ':');
            if (colons == 1)
            {
                var parts = dest.Split(':');
                host = parts[0];
                if (int.TryParse(parts[1], out int p))
                    port = p;
                return host.Length > 0;
            }

            host = dest;
            return true;
        }

        #endregion

        /// <summary>
        /// For every ProfileGeneric in _objects, replace each CaptureObject's key
        /// with the corresponding instance that already lives in Items.  If a
        /// referenced object is missing from Items it is added so Gurux can still
        /// encode the column.
        /// </summary>
        private void RewireProfileCaptureObjects()
        {
            foreach (var profile in _objects.OfType<GXDLMSProfileGeneric>().ToList())
            {
                if (profile.CaptureObjects.Count == 0) continue;

                CoreLog.Debug($"Re-wiring CaptureObjects for {profile.LogicalName} " +
                                  $"({profile.CaptureObjects.Count} columns, {profile.Buffer.Count} rows)");

                var rewired = new List<GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>>();
                foreach (var kv in profile.CaptureObjects)
                {
                    var real = Items.FindByLN(kv.Key.ObjectType, kv.Key.LogicalName);
                    if (real == null)
                    {
                        // Referenced object not in Items — register the stub so Gurux
                        // can at least determine the column DataType.
                        CoreLog.Warn($"  WARNING: {kv.Key.ObjectType} {kv.Key.LogicalName} not in Items — adding stub");
                        Items.Add(kv.Key);
                        real = kv.Key;
                    }
                    rewired.Add(new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(real, kv.Value));
                }

                profile.CaptureObjects.Clear();
                profile.CaptureObjects.AddRange(rewired);
            }
        }

        private void InitializeObjects()
        {

            var clock = new GXDLMSClock
            {
                LogicalName = "0.0.1.0.0.255",
                Time = DateTime.Now,
                Status = ClockStatus.Ok
            };

            var cumKwh = new GXDLMSRegister
            {
                LogicalName = "1.0.1.8.0.255",
                Scaler = 0,
                Unit = Unit.ActiveEnergy,
                Value = 1
            };

            var cumKvah = new GXDLMSRegister
            {
                LogicalName = "1.0.9.8.0.255",
                Scaler = 0,
                Unit = Unit.ApparentEnergy,
                Value = 1
            };
            var exportkwh = new GXDLMSRegister
            {
                LogicalName = "1.0.2.8.0.255",
                Scaler = 0,
                Unit = Unit.ActiveEnergy,
                Value = 1
            };
            var exportkvah = new GXDLMSRegister
            {
                LogicalName = "1.0.10.8.0.255",
                Scaler = 0,
                Unit = Unit.ApparentEnergy,
                Value = 1
            };
            var invocationCounter = new GXDLMSData
            {
                LogicalName = "0.0.43.1.3.255",
                Value = Convert.ToUInt32(1)
            };
            invocationCounter.SetAccess(1, AccessMode.Read);
            invocationCounter.SetAccess(2, AccessMode.ReadWrite);

            _objects.Add(cumKwh);
            _objects.Add(cumKvah);
            _objects.Add(exportkwh);
            _objects.Add(exportkvah);
            _objects.Add(clock);
            _objects.Add(invocationCounter);

            clock.SetDataType(2, DataType.DateTime);
            cumKwh.SetDataType(2, DataType.UInt32);
            cumKvah.SetDataType(2, DataType.UInt32);
            exportkwh.SetDataType(2, DataType.UInt32);
            exportkvah.SetDataType(2, DataType.UInt32);
            invocationCounter.SetDataType(2, DataType.UInt32);

            AddDailyLoadProfile(clock, cumKwh, cumKvah, exportkwh, exportkvah);
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
                Secret = _meter.HLSKey,
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
        //private void OnDataReceived(object? sender, ReceiveEventArgs e)
        //{
        //    byte[] data;
        //    try
        //    {
        //        data = (byte[])e.Data;

        //        //CoreLog.Debug($"Hex Received: {BitConverter.ToString(data)}");

        //        byte[] reply = HandleRequest(data);
        //        if (reply.Length != 0)
        //        {
        //            //CoreLog.Debug($"Sending reply: {BitConverter.ToString(reply)}");
        //            _network.Send(reply, e.SenderInfo);
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        CoreLog.Debug($"DLMS error: {ex.Message}");
        //        //CoreLog.Debug($"Data Received: {BitConverter.ToString(data)}");
        //        CoreLog.Debug($"Stack: {ex.StackTrace}");
        //    }
        //}

        protected override void PreRead(ValueEventArgs[] args)
        {
            foreach (var arg in args)
            {
                try
                {
                    CoreLog.Debug($"PreRead: {arg.Target.ObjectType} - {arg.Target.LogicalName}, Attr={arg.Index}");

                    if (arg.Target is GXDLMSAssociationLogicalName && arg.Index == 2)
                    {
                        var assoc = arg.Target as GXDLMSAssociationLogicalName;
                    }

                    if (arg.Target.LogicalName == "0.0.43.1.3.255" && arg.Index == 2)
                    {
                        var ic0 = Items.FindByLN(ObjectType.Data, "0.0.43.1.0.255") as GXDLMSData;

                        if (ic0 != null)
                        {
                            CoreLog.Debug($"IC Value : {ic0.Value}");
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
                catch (Exception ex)
                {
                    CoreLog.Error($"PreRead ERROR: {arg.Target?.LogicalName} attr{arg.Index}: {ex}");
                }
            }
        }
        //public void Start()
        //{
        //    Initialize(true);
        //    _network.OnReceived += OnDataReceived;
        //    _network.Open();
        //    CoreLog.Debug($"DLMS Meter {_meter.MeterNo} listening on port {_network.Port}");
        //}
        

        //public void Stop()
        //{
        //    _network.Close();
        //}

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
            // Routing to the correct meter is done by IPv6 before this session ever sees a
            // frame (MeterSessionManager keys sessions by meter IP), and each session serves
            // exactly one meter. So we accept whatever DLMS server (lower) address the HES
            // dialed rather than rejecting on it — the logical device address is fixed on a
            // real meter and the IP is the distinguisher here. Per-meter distinctness lives
            // in the crypto identity (system title / keys), not this address.
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

            if (arg.Target is GXDLMSProfileGeneric)
                return AccessMode.Read;

            if (arg.Target is GXDLMSData && arg.Index == 2)
                return AccessMode.ReadWrite;

            if (arg.Target is GXDLMSPushSetup)
                return AccessMode.ReadWrite;

            return AccessMode.Read;
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
            if (password != null)
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
            CoreLog.Debug($"Client connected");
        }

        protected override void Disconnected(GXDLMSConnectionEventArgs connectionInfo)
        {
            CoreLog.Debug( $"DLMS client Disconnected");
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
        #region Profiles
        private void AddDailyLoadProfile(GXDLMSClock clock, GXDLMSRegister cumKwh, GXDLMSRegister cumKvah, GXDLMSRegister exportKwh, GXDLMSRegister exportKvah)
        {
            var loadProfile = new GXDLMSProfileGeneric
            {
                LogicalName = "1.0.99.2.0.255",
                CapturePeriod = 86400,
                ProfileEntries = 10,
                SortMethod = SortMethod.FiFo
            };

            loadProfile.CaptureObjects.Add(
                new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(
                    clock, new GXDLMSCaptureObject(2, 0)));
            loadProfile.CaptureObjects.Add(
                new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(
                    cumKwh, new GXDLMSCaptureObject(2, 0)));
            loadProfile.CaptureObjects.Add(
                new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(
                    cumKvah, new GXDLMSCaptureObject(2, 0)));
            loadProfile.CaptureObjects.Add(
                new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(
                    exportKwh, new GXDLMSCaptureObject(2, 0)));
            loadProfile.CaptureObjects.Add(
                new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(
                    exportKvah, new GXDLMSCaptureObject(2, 0)));

            loadProfile.SetAccess(2, AccessMode.Read);
            loadProfile.SortObject = clock;
            loadProfile.SortAttributeIndex = 2;

            DateTime start = DateTime.UtcNow.Date.AddDays(-10);

            for (int i = 0; i < 10; i++)
            {
                loadProfile.Buffer.Add(new object[]
                {
                    new GXDateTime(start.AddDays(i)),
                    1000 + (i * 10),
                    2000 + (i * 10),
                    300 + (i * 10),
                    150 + (i * 10)
                            });
            }

            loadProfile.EntriesInUse = (uint)loadProfile.Buffer.Count;
            loadProfile.SetDataType(2, DataType.Structure);
            _objects.Add(loadProfile);
        }
        #endregion
        #region Unused
        protected override void PreAction(ValueEventArgs[] args)
        {
        }

        protected override void PostRead(ValueEventArgs[] args)
        {
        }

        protected override void PostWrite(ValueEventArgs[] args)
        {
            foreach (var arg in args)
            {
                var obis = arg.Target.LogicalName;
                if (arg.Target is GXDLMSRegister || arg.Target is GXDLMSData)
                {
                    _meter.SetValue(obis, arg.Value);
                    CoreLog.Debug($"Synchronized client write to meter: {arg.Target.ObjectType} - {obis} = {arg.Value}");
                }
            }
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
        #endregion
    }
}
