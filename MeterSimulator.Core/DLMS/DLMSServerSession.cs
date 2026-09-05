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
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MeterSimulator.DLMS
{
    /// <summary>Outcome of a single meter's on-demand push: PushSetups sent vs. failed.</summary>
    public readonly record struct PushSendResult(int Sent, int Failed)
    {
        /// <summary>True if the meter had at least one PushSetup and every one was sent.</summary>
        public bool AllSent => Failed == 0 && Sent > 0;
    }

    public class DLMSServerSession : GXDLMSSecureServer
    {
        private readonly DLMSMeter _meter;
        //private readonly GXNet _network;
        private readonly GXDLMSObjectCollection _objects = new();

        /// <summary>
        /// The SHARED template model (see <see cref="TemplateModelCache"/>) — borrowed, not owned.
        /// Read-only: writing to anything in here would leak across every meter using this template.
        /// </summary>
        private readonly GXDLMSObjectCollection _objectsFromFile;

        // ── Push (outbound DataNotification) ──────────────────────────────────
        // The meter acts as a TCP CLIENT for push: the session BUILDS the
        // DataNotification frames from each PushSetup's push_object_list and the host
        // (TcpPushSender) sends them.  Gurux does NOT transmit push itself, so the
        // encoder (_notify) is ours.
        private readonly PushConfig? _pushConfig;

        /// <summary>
        /// The outbound DataNotification encoder — a SECOND full DLMS stack. Created on first push
        /// rather than in the constructor: push is on-demand, so the overwhelming majority of meters
        /// never need one, and at fleet scale building it eagerly was pure per-meter overhead.
        /// </summary>
        private GXDLMSSecureNotify? _notify;

        /// <summary>
        /// Push briefly writes THIS meter's values onto the shared template objects so Gurux can
        /// encode them, so the mutate→encode window must be exclusive across every meter — hence a
        /// process-wide lock rather than a per-session one.
        ///
        /// This does not block the pull path: HES reads are answered from the per-meter store via
        /// <see cref="PreRead"/> and never consult these objects' values, and profile reads encode
        /// from Buffer rows rather than live objects. Only push encoding serialises, which is
        /// in-memory and fast; the socket IO (host-side TcpPushSender) is outside it entirely.
        /// </summary>
        private static readonly object PushEncodeLock = new();

        // The meter's OWN address, bound as the LOCAL endpoint of the outbound push socket so the
        // receiver correlates the push to this meter by source IP (see remarks on SendFrames). Null
        // for NICs with no per-meter IP (MQTT) or when the host didn't supply one — push then leaves
        // from the host's default source address.
        private readonly IPAddress? _sourceAddress;

        public DLMSServerSession(DLMSMeter meter, string templatePath, PushConfig? pushConfig = null, IPAddress? sourceAddress = null)
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
            _sourceAddress = sourceAddress;

            Settings.Authentication = Authentication.High;
            //_network = new GXNet(NetworkType.Tcp, port)
            //{
            //    Trace = TraceLevel.Verbose
            //};

            Settings.MaxPduSize = 65535;

            Items.Clear();

            // Template (DLMS object model) is chosen per-batch and resolved to a path by
            // the host (MeterSessionManager) — no hardcoded/machine-specific path here.
            //
            // SHARED, not loaded per meter: the cache parses each template exactly once and every
            // meter built from it references the same objects (see TemplateModelCache for why this
            // is safe). _objectsFromFile therefore holds borrowed, READ-ONLY objects — never write
            // to them; per-meter divergence belongs in _meter.
            _objectsFromFile = TemplateModelCache.Shared.Get(templatePath);

            // Seed this meter's own value store from the template's defaults. Reads are answered
            // from here (see PreRead), so the shared objects are never consulted for a value and
            // never need to be written to.
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

            // The template bakes in a single serial (e.g. "SA1231166") and is SHARED by every meter,
            // so this meter's own serial goes into ITS value store — never onto the shared object,
            // which would give every meter the last-built meter's serial. Must run after the seeding
            // loop above, which would otherwise overwrite it with the template's serial.
            // (HES reconciles IP-vs-meterno using the serial in the DLMS payload.)
            ApplySerialOverride();

            // InitializeObjects() (legacy, pre-template hardcoded object set) must stay disabled:
            // it registers its own Clock/registers/Daily Load Profile at the SAME OBIS the XML
            // template uses, and since it runs before the XML merge loop below, that loop's
            // dedup-by-(ObjectType, LogicalName) check finds these already registered and silently
            // skips the real XML objects — orphaning them entirely, not just shadowing their data.
            // Re-enabling this is what broke "read the Daily Load Profile from the XML template":
            // every read resolved to this hardcoded stand-in instead, for every meter, regardless
            // of template. Daily Load Profile reads now go through Gurux's native selective-access
            // handling on the real XML profile, same as every other profile.
            // InitializeObjects();
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

        // ApplyPushDestinationOverride was removed with the move to a SHARED template model: it
        // wrote PushSetup.Destination onto objects every meter now shares, so the last meter built
        // would have decided the destination for the whole fleet. The destination is supplied per
        // send instead (host-side TcpPushSender), which is also what lets the dashboard change it
        // at runtime.

        /// <summary>
        /// OBIS of the meter serial number (a GXDLMSData string, attr 2).
        /// </summary>
        private const string SerialNumberLN = "0.0.96.1.0.255";

        /// <summary>
        /// Records this meter's own serial (<see cref="DLMSMeter.MeterNo"/>, "MY" + 9-digit index)
        /// in its per-meter value store, which is what <see cref="PreRead"/> answers from. The
        /// shared template object is deliberately left untouched.
        /// </summary>
        private void ApplySerialOverride()
        {
            if (_objectsFromFile.FindByLN(ObjectType.Data, SerialNumberLN) is not GXDLMSData)
            {
                CoreLog.Debug($"[Serial] {_meter.MeterNo}: no {SerialNumberLN} in template, skipping");
                return;
            }

            _meter.SetValue(SerialNumberLN, _meter.MeterNo);
            CoreLog.Debug($"[Serial] {_meter.MeterNo}: {SerialNumberLN} set for this meter");
        }

        /// <summary>
        /// Builds the outbound push payloads for this meter — one complete DataNotification per
        /// sendable PushSetup — and returns them. Nothing is transmitted here: this session is
        /// transport-agnostic, so it knows how to ENCODE a push but not WHERE or HOW to send it.
        /// The NIC layer decides that — TCP opens a socket to the meter's push target, the MQTT NICs
        /// wrap each payload for their broker topic (see the codecs).
        ///
        /// <para>
        /// One payload per PushSetup: that list IS the buffer, fixed by the template at load time.
        /// A PushSetup with an empty <c>push_object_list</c> (some templates ship the Alert setup
        /// that way) would encode a DataNotification carrying no data, so it is skipped rather than
        /// emitting a meaningless frame. Live meter values are synced in first
        /// (<see cref="SyncPushValues"/>), because Gurux reads each object's value directly here, not
        /// through the server's PreRead.
        /// </para>
        /// </summary>
        /// <param name="useCiphering">true → general-glo-ciphering with the meter's keys; false → plaintext.</param>
        /// <returns>One byte[] per PushSetup — each a complete DLMS wrapper DataNotification frame.</returns>
        public IReadOnlyList<byte[]> BuildPushPayloads(bool useCiphering)
        {
            var pushObjects = _objects.OfType<GXDLMSPushSetup>()
                .Where(p => p.PushObjectList.Count > 0)
                .ToList();

            if (pushObjects.Count == 0)
            {
                CoreLog.Warn(
                    $"[Push] {_meter.MeterNo}: no PushSetup with a non-empty push_object_list — " +
                    "nothing to send. Use a template whose PushSetup defines an ObjectList " +
                    "(e.g. Values_SZ0000014HP.xml).");
                return Array.Empty<byte[]>();
            }

            var payloads = new List<byte[]>(pushObjects.Count);
            foreach (var push in pushObjects)
            {
                // SyncPushValues writes this meter's values onto the SHARED template objects so
                // Gurux can encode them, so mutate→encode must be exclusive across every meter.
                // See PushEncodeLock — the send itself happens outside, host-side.
                byte[][] frames;
                lock (PushEncodeLock)
                {
                    SyncPushValues(push);
                    ConfigureNotifyCiphering(useCiphering);
                    frames = Notify.GeneratePushSetupMessages(DateTime.UtcNow, push);
                }

                // GeneratePushSetupMessages returns the wrapper frames for this PushSetup — one for
                // an unfragmented push. Concatenate into a single payload: over TCP the frames are
                // written back-to-back anyway (each is length-prefixed and self-delimiting), and the
                // MQTT NICs carry one PushSetup as one message.
                payloads.Add(Concat(frames));
            }

            return payloads;
        }

        private static byte[] Concat(byte[][] frames)
        {
            if (frames.Length == 1)
                return frames[0];

            int total = 0;
            foreach (var f in frames) total += f.Length;
            var buffer = new byte[total];
            int offset = 0;
            foreach (var f in frames)
            {
                Buffer.BlockCopy(f, 0, buffer, offset, f.Length);
                offset += f.Length;
            }

            return buffer;
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

        /// <summary>
        /// The DataNotification encoder for this meter, built on first use. Callers are already
        /// inside <see cref="PushEncodeLock"/>, so no additional synchronisation is needed here.
        /// Meter is the source (server address); the client/HES is the destination address.
        /// </summary>
        private GXDLMSSecureNotify Notify =>
            _notify ??= new GXDLMSSecureNotify(
                true, _meter.ClientAddress, _meter.ServerAddress, InterfaceType.WRAPPER);

        /// <summary>Applies plaintext or general-glo-ciphering to the notify encoder.</summary>
        private void ConfigureNotifyCiphering(bool useCiphering)
        {
            if (useCiphering)
            {
                Notify.Ciphering.Security = Security.AuthenticationEncryption;
                Notify.Ciphering.SystemTitle = _meter.SystemTitle;
                Notify.Ciphering.BlockCipherKey = _meter.BlockCipherKey;
                Notify.Ciphering.AuthenticationKey = _meter.AuthenticationKey;
            }
            else
            {
                Notify.Ciphering.Security = Security.None;
            }
        }

        /// <summary>
        /// The meter's own address, for a NIC that wants to originate a push from it (TCP binds this
        /// as the socket's source so HES correlates by source IP). Null for meters with no per-meter
        /// address (the MQTT NICs, where the node id carries the identity instead).
        /// </summary>
        public IPAddress? SourceAddress => _sourceAddress;

        // The push TRANSPORT (open a socket / bind the source / publish to a broker) deliberately no
        // longer lives here. This session encodes a push and stops there; the NIC layer decides
        // where and how to send it — see ManyMeterSimulator's push sender for TCP and the codecs for
        // the MQTT NICs.

        #endregion

        /// <summary>
        /// Ensures every object a profile captures is present in THIS session's Items, so Gurux can
        /// resolve each column's DataType while encoding.
        ///
        /// Deliberately read-only with respect to the profiles themselves. It used to rebuild each
        /// profile's CaptureObjects list (Clear + AddRange), which is now a shared-state write: the
        /// profiles belong to the shared template model, so two sessions constructing concurrently
        /// would have one clearing the list while the other enumerated it —
        /// "Collection was modified" — and, worse, could leave a profile half-rewired.
        ///
        /// The rebuild is also unnecessary: <see cref="MeterObjectLoader"/> already points every
        /// CaptureObject at the canonical instance within the same collection, once, at template
        /// load. Items is per-session, so topping it up here remains safe.
        /// </summary>
        private void RewireProfileCaptureObjects()
        {
            foreach (var profile in _objects.OfType<GXDLMSProfileGeneric>().ToList())
            {
                if (profile.CaptureObjects.Count == 0) continue;

                foreach (var kv in profile.CaptureObjects)
                {
                    if (Items.FindByLN(kv.Key.ObjectType, kv.Key.LogicalName) == null)
                    {
                        // Referenced object not in Items — register it so Gurux can still determine
                        // the column DataType. Adds to the per-session Items, never to the profile.
                        CoreLog.Debug($"  {kv.Key.ObjectType} {kv.Key.LogicalName} not in Items — registering");
                        Items.Add(kv.Key);
                    }
                }
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
                // 0x10 = 16, the standard DLMS Public client. HES dials it as `0x10` in
                // ClientFactory.CreateClient(true, 0x10, 1, Authentication.None, ...) — writing it
                // as decimal 10 here made the SAP disagree with every real client.
                ClientSAP = 16
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
                    // HES opens this association with context 2.16.756.5.8.1.3 — LN referencing
                    // WITH ciphering — because its secure client sets Security.AuthenticationEncryption.
                    // Declaring plain LogicalName here means Gurux matches no association for the
                    // ciphered AARQ and answers nothing at all, which is invisible on both sides.
                    ContextId = ApplicationContextName.LogicalNameWithCiphering
                },
                Secret = _meter.HLSKey,
                // 0x30 = 48, the US (utility setting) client HES uses for the ciphered HLS
                // association: CreateSecureClient(true, 0x30, 1, Authentication.High, HLSUSSecret, ...).
                // As decimal 30 this association could never be matched, so the secure AARQ went
                // unanswered and the HES pull stalled after its Step 4.
                ClientSAP = 48
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

                    // Invocation counter: the client reads …43.1.3.255 but the live value is kept
                    // under …43.1.0.255 in THIS meter's store (PreWrite puts it there). Reading the
                    // shared object here would hand every meter the same counter.
                    if (arg.Target.LogicalName == "0.0.43.1.3.255" && arg.Index == 2)
                    {
                        var ic = _meter.GetValue("0.0.43.1.0.255");
                        if (ic != null)
                        {
                            arg.Value = ic;
                            arg.Handled = true;
                            continue;
                        }
                    }

                    // The clock lives on the SHARED template object, seeded once when the template
                    // was parsed — so serving it from there would freeze every meter's clock at the
                    // moment of first parse. Answer with the current time instead.
                    if (arg.Target is GXDLMSClock && arg.Index == 2)
                    {
                        arg.Value = new GXDateTime(DateTime.UtcNow);
                        arg.Handled = true;
                        continue;
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

        /// <summary>
        /// Absorbs every client write into THIS meter's value store.
        ///
        /// Setting <c>Handled = true</c> is mandatory, not an optimisation. When the server leaves a
        /// write unhandled, Gurux calls <c>IGXDLMSBase.SetValue</c> on the target object
        /// (GXDLMSLNCommandHandlers, "else if (!e.Handled ...)") — and those objects are SHARED by
        /// every meter using this template, so one meter's write would silently become every
        /// meter's value.
        ///
        /// Note the matching trap: Gurux invokes PostWrite inside that same unhandled branch, so
        /// once a write is marked handled PostWrite never runs. The value therefore has to be stored
        /// HERE; relying on PostWrite would accept writes and silently drop them.
        /// </summary>
        protected override void PreWrite(ValueEventArgs[] args)
        {
            foreach (var arg in args)
            {
                // The invocation counter is mirrored onto a different object (…43.1.0.255) than the
                // one the client writes (…43.1.3.255), so it keeps its own mapping.
                if (arg.Target.LogicalName == "0.0.43.1.3.255" && arg.Index == 2)
                {
                    _meter.SetValue("0.0.43.1.0.255", arg.Value);
                    arg.Handled = true;
                    continue;
                }

                if ((arg.Target is GXDLMSRegister || arg.Target is GXDLMSData) && arg.Index == 2)
                {
                    _meter.SetValue(arg.Target.LogicalName, arg.Value);
                    arg.Handled = true;
                    CoreLog.Debug(
                        $"[Write] {_meter.MeterNo}: {arg.Target.ObjectType} {arg.Target.LogicalName} = {arg.Value}");
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
