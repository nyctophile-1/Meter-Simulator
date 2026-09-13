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

        /// <summary>
        /// This meter's own value store. Exposed so batch-level profile simulation
        /// (<c>BatchProfileSimulationState</c>) can push a newly generated capture's register/data
        /// values into every materialized meter of a batch — reads are answered from here (see
        /// <see cref="PreRead"/>), not from the shared object graph, so a capture generated once for
        /// the whole batch still needs this per-meter update for live pulls to see it.
        /// </summary>
        public DLMSMeter Meter => _meter;

        private readonly string _templatePath;
        private readonly bool _shiftProfileTimestamps;
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

        public DLMSServerSession(
            DLMSMeter meter,
            string templatePath,
            PushConfig? pushConfig = null,
            IPAddress? sourceAddress = null,
            bool initializeValues = true,
            bool shiftProfileTimestamps = true)
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
            _templatePath = templatePath;
            _shiftProfileTimestamps = shiftProfileTimestamps;
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
            _objectsFromFile = TemplateModelCache.Shared.Get(templatePath, shiftProfileTimestamps);

            // Seed this meter's own value store from the template's defaults. Reads are answered
            // from here (see PreRead), so the shared objects are never consulted for a value and
            // never need to be written to.
            foreach (var obj in initializeValues ? _objectsFromFile : new GXDLMSObjectCollection())
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
            if (initializeValues)
            {
                ApplySerialOverride();
                ApplyDeviceIdOverride();
            }

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

        /// <summary>A separate association over this meter's state, without reseeding its values.</summary>
        public DLMSServerSession CreateReadAssociation()
        {
            var association = new DLMSServerSession(
                _meter,
                _templatePath,
                initializeValues: false,
                shiftProfileTimestamps: _shiftProfileTimestamps);
            association.Initialize(true);
            return association;
        }

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
        /// OBIS of the Device ID (a GXDLMSData string, attr 2) — a DIFFERENT object from
        /// <see cref="SerialNumberLN"/>, and the one the push structure actually carries as its
        /// meter-identifying element (see BuildPushPayloads' ObjectList). Missed by the original
        /// serial override, so every meter on a shared template pushed the template's one static
        /// value ("CRYSA1231166" for SA1231166HP_values.xml) — the HES could only ever resolve one
        /// meter per template, since they were all indistinguishable on the wire.
        /// </summary>
        private const string DeviceIdLN = "0.0.96.1.2.255";

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
        /// Same per-meter treatment as <see cref="ApplySerialOverride"/>, for the Device ID object
        /// pushed as the meter-identifying element of a push structure. Keeps the template's "CRY"
        /// prefix convention (its static value is "CRY" + the serial, e.g. "CRYSA1231166") while
        /// making the value unique per meter.
        /// </summary>
        private void ApplyDeviceIdOverride()
        {
            if (_objectsFromFile.FindByLN(ObjectType.Data, DeviceIdLN) is not GXDLMSData)
            {
                CoreLog.Debug($"[DeviceId] {_meter.MeterNo}: no {DeviceIdLN} in template, skipping");
                return;
            }

            _meter.SetValue(DeviceIdLN, "CRY" + _meter.MeterNo);
            CoreLog.Debug($"[DeviceId] {_meter.MeterNo}: {DeviceIdLN} set for this meter");
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
        /// <param name="pushSetupLogicalName">
        /// When set, restricts sending to the ONE PushSetup with this LN (e.g. "0.0.25.9.0.255" for
        /// Instant, "0.5.25.9.0.255" for Block Load) — each profile type is its own PushSetup at its
        /// own channel OBIS, because that LN is also the "SelfLN" element the HES uses to dispatch to
        /// the matching parser (see BuildPushPayloads' Item[1] in each flat structure). Null (the
        /// default) sends every non-empty PushSetup the template configures.
        ///
        /// <para>
        /// If the template has no PushSetup at this LN but it's one of the well-known dispatch codes
        /// (see <see cref="BuildEphemeralPushSetup"/>) and the corresponding profile/values exist,
        /// this builds the push directly from that pull data instead of requiring a template author
        /// to declare a PushSetup object — the meter can push anything it can already answer on
        /// pull. A template-declared PushSetup always takes priority when present, since it may
        /// carry a deliberately customized field list.
        /// </para>
        /// </param>
        /// <returns>One byte[] per PushSetup — each a complete DLMS wrapper DataNotification frame.</returns>
        public IReadOnlyList<byte[]> BuildPushPayloads(bool useCiphering, string? pushSetupLogicalName = null)
        {
            var pushObjects = _objects.OfType<GXDLMSPushSetup>()
                .Where(p => p.PushObjectList.Count > 0)
                .Where(p => pushSetupLogicalName == null || p.LogicalName == pushSetupLogicalName)
                .ToList();

            if (pushObjects.Count == 0 && pushSetupLogicalName != null
                && BuildEphemeralPushSetup(pushSetupLogicalName) is GXDLMSPushSetup ephemeral)
            {
                pushObjects.Add(ephemeral);
            }

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
                    // A push that represents a profile's row (Block Load, Daily, Billing, Events —
                    // any GXDLMSProfileGeneric) needs its per-row values pulled from that profile's
                    // latest buffer entry first. Scoped to THIS push and synced immediately before
                    // encoding: with several profile-backed pushes in the same template, syncing
                    // globally up front would let each one's synthetic RTC OBIS clobber the last
                    // before it's actually encoded.
                    SyncProfileBackedPushValues(push);
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

        /// <summary>Available push setups without encoding or advancing invocation counters.</summary>
        public IReadOnlyList<string> GetPushSetupLogicalNames() => _objects.OfType<GXDLMSPushSetup>()
            .Where(p => p.PushObjectList.Count > 0).Select(p => p.LogicalName).Distinct().ToArray();

        /// <summary>
        /// Serializes the complete current object model to a working XML path. The caller owns
        /// atomic replacement and validation, because persistence policy belongs to the host.
        /// Batch-level profile simulation calls this via one representative meter's session — every
        /// meter in the batch shares the same object graph and identical values, so any one of them
        /// produces a correct, complete snapshot.
        /// </summary>
        public void SaveWorkingModel(string destinationPath)
        {
            if (string.IsNullOrWhiteSpace(destinationPath))
            {
                throw new ArgumentException("A working XML destination is required.", nameof(destinationPath));
            }

            if (_shiftProfileTimestamps)
            {
                throw new InvalidOperationException(
                    "Only an isolated profile-simulation working model may be saved. " +
                    "The shared template model is read-only.");
            }

            // A profile row is persisted directly on the working object graph. Register and Data
            // values, however, are deliberately held in this meter's own value store while the
            // server is running. Copy them onto this *isolated* graph before serialization so a
            // restart seeds the same current values that a pull would have returned.
            SyncWorkingModelValuesForPersistence();

            _objectsFromFile.Save(destinationPath, new GXXmlWriterSettings
            {
                Values = true,
                IgnoreDefaultValues = false,
                // false converts UTC captures through the host timezone; true keeps meter time.
                UseMeterTime = true,
            });

            // Gurux's meter-time writer appends Z to a value that already carries +00:00, yielding
            // +00:00Z. Its own XML reader expands the Z into another +00:00 and cannot reload it.
            // Normalize the redundant UTC suffix while the XML is still a private temp snapshot.
            string xml = File.ReadAllText(destinationPath);
            File.WriteAllText(destinationPath, xml.Replace("+00:00Z", "Z", StringComparison.Ordinal));
        }

        private void SyncWorkingModelValuesForPersistence()
        {
            foreach (GXDLMSObject obj in _objectsFromFile)
            {
                switch (obj)
                {
                    case GXDLMSRegister register:
                    {
                        object? value = _meter.GetValue(register.LogicalName);
                        if (value is not null)
                        {
                            register.Value = value;
                        }

                        break;
                    }
                    case GXDLMSData data:
                    {
                        object? value = _meter.GetValue(data.LogicalName);
                        if (value is not null)
                        {
                            data.Value = value;
                        }

                        break;
                    }
                }
            }
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
                        // A per-meter override (e.g. SyncProfileBackedPushValues, which needs this
                        // push's timestamp to be the buffered row's own captured time, not "now")
                        // wins when set; otherwise a Clock in a push list means "the time of this
                        // push", so it defaults to now.
                        var clockOverride = _meter.GetValue(clk.LogicalName);
                        clk.Time = clockOverride is GXDateTime gClockOverride ? gClockOverride : new GXDateTime(DateTime.UtcNow);
                        break;
                }
            }
        }

        /// <summary>
        /// OBIS of a Clock dedicated to a profile-backed push's own RTC slot. Deliberately NOT the
        /// shared Clock ("0.0.1.0.0.255") that a non-profile push (e.g. Instant) uses to mean "now"
        /// — this one must carry the captured row's own time instead, rounded to the source
        /// profile's own capture period, not whatever moment the operator happened to click "Send
        /// Push". Shared by every profile-backed push in turn — safe because each is synced and
        /// encoded immediately, one at a time (see the loop in <see cref="BuildPushPayloads"/>).
        /// </summary>
        private const string ProfileBackedPushRtcLN = "0.0.1.0.1.255";

        /// <summary>
        /// Copies the LATEST row of whichever profile buffer feeds this PushSetup onto this meter's
        /// per-attribute value store — the same store <see cref="SyncPushValues"/> already reads
        /// from — so a flat PushSetup (Block Load, Daily, Billing, Events, or any future profile
        /// type) carries real data without any special-casing in the encode path itself.
        ///
        /// <para>
        /// Gated on whether this push's own <c>PushObjectList</c> contains a Clock entry at
        /// <see cref="ProfileBackedPushRtcLN"/> specifically — a deliberate template-authoring
        /// convention, not an inferred heuristic: a non-profile push (Instant, Alert) uses the
        /// ordinary "now" clock ("0.0.1.0.0.255") instead. This gate matters because register OBIS
        /// overlap ALONE is not a safe signal — common registers like AverageVoltage can legitimately
        /// appear in more than one profile's <c>CaptureObjects</c> (and even in a non-profile push's
        /// flat live-value list), so checking object overlap before this gate previously misfired:
        /// it treated Instant's push as profile-backed because it happened to share a register with
        /// some unrelated profile, corrupting its live value and crashing the encoder.
        /// </para>
        ///
        /// <para>
        /// Once gated in, the source profile is found by object overlap: a register/data OBIS
        /// referenced by both a <see cref="GXDLMSProfileGeneric"/>'s <c>CaptureObjects</c> and this
        /// push's own <c>PushObjectList</c> is the same shared object instance (Gurux's loader
        /// dedupes by OBIS). Picks the profile with the MOST overlapping objects, not just the first
        /// match, in case more than one profile-backed push shares a template — the push's list was
        /// authored to mirror ONE profile's entire column set, so the true source profile shares far
        /// more objects with it than any other profile could by coincidence.
        /// </para>
        ///
        /// <para>
        /// "Latest" means the row with the MAXIMUM timestamp, found explicitly — NOT
        /// <c>Buffer[^1]</c> (the last array slot). A live push confirmed a Block Load buffer can be
        /// chronologically sorted for indices 0..N-2 but carry one stray, over-a-month-old row at the
        /// very end (a data artifact, not something this code should have to assume away). Trusting
        /// array position silently pushed that stale row's timestamp on every send.
        /// <see cref="MeterObjectLoader.ShiftBufferTimestamps"/> already computes "latest" the same
        /// way, via Max() — this matches it instead of a second, weaker assumption.
        /// </para>
        /// </summary>
        private void SyncProfileBackedPushValues(GXDLMSPushSetup push)
        {
            bool isProfileBacked = push.PushObjectList
                .Any(kv => kv.Key is GXDLMSClock && kv.Key.LogicalName == ProfileBackedPushRtcLN);
            if (!isProfileBacked)
            {
                return;
            }

            var pushObjects = new HashSet<GXDLMSObject>(push.PushObjectList.Select(kv => kv.Key));
            GXDLMSProfileGeneric? profile = _objectsFromFile.OfType<GXDLMSProfileGeneric>()
                .Where(p => p.Buffer.Count > 0)
                .Select(p => (Profile: p, Overlap: p.CaptureObjects.Count(co => pushObjects.Contains(co.Key))))
                .Where(candidate => candidate.Overlap > 0)
                .OrderByDescending(candidate => candidate.Overlap)
                .Select(candidate => candidate.Profile)
                .FirstOrDefault();

            if (profile is null)
            {
                return;
            }

            if (_shiftProfileTimestamps)
            {
                EnsureBufferFreshness(profile);
            }

            object[]? latestRow = null;
            DateTimeOffset latestTime = DateTimeOffset.MinValue;
            foreach (object[] row in profile.Buffer)
            {
                if (row.Length > 0 && row[0] is GXDateTime candidate && candidate.Value > latestTime)
                {
                    latestTime = candidate.Value;
                    latestRow = row;
                }
            }

            if (latestRow is null || latestRow[0] is not GXDateTime rowTime)
            {
                CoreLog.Debug($"[Push] {_meter.MeterNo}: {profile.LogicalName} buffer has no row with a usable timestamp, skipping sync");
                return;
            }

            // DateTimeOffset.DateTime always comes back Kind=Unspecified, whatever the offset was
            // — so wrapping "rounded" in GXDateTime as-is would make Gurux compute its wire offset
            // from TimeZoneInfo.Local (the HOST machine's zone) instead of encoding it as the UTC
            // value it actually is. Force Kind=Utc so the digits transmit with offset 0 regardless
            // of what timezone the process happens to run in.
            //
            // Always rounds to the nearest half hour, unconditionally — NOT derived from the
            // profile's own CapturePeriod (Block Load's is 900s/15min in at least one real template,
            // not 30min as its own capture cadence would suggest; the half-hour grid is an RTC wire
            // convention independent of it). This is a pure carry-over of the original Block-Load-only
            // behavior, generalized to whichever profile is found rather than changed: a calendar
            // boundary (Daily's midnight, Billing's month-start) is already exactly on a half-hour
            // grid, so rounding it is a no-op — nothing here needed to change for those to work.
            DateTime rounded = DateTime.SpecifyKind(RoundToNearestPeriod(rowTime.Value.DateTime, TimeSpan.FromMinutes(30)), DateTimeKind.Utc);
            _meter.SetValue(ProfileBackedPushRtcLN, new GXDateTime(rounded));

            // Column 0 is the row's own timestamp (already consumed above) — everything after it
            // lines up 1:1, in order, with CaptureObjects[1..].
            var captureObjects = profile.CaptureObjects;
            for (int i = 1; i < captureObjects.Count && i < latestRow.Length; i++)
            {
                _meter.SetValue(captureObjects[i].Key.LogicalName, latestRow[i]);
            }

            CoreLog.Debug($"[Push] {_meter.MeterNo}: {profile.LogicalName} synced from row {rowTime.Value:O} -> {rounded:O}");
        }

        /// <summary>
        /// The well-known profile OBIS behind each fixed, buffer-backed dispatch code a real HES
        /// recognizes (confirmed against vayu-common's own push dispatch table — see
        /// docs/profile-simulation/plan.md §3a) — the SAME identity <c>MeterDataSnapshotReader</c>
        /// already uses elsewhere in this codebase to name these profiles, kept here as an explicit,
        /// reviewed table rather than inferred, because guessing this mapping wrong would silently
        /// mislabel one profile's data as another's. Public so the UI (which needs to know whether a
        /// profile CAN be pushed even without a declared PushSetup) shares this exact table instead
        /// of duplicating it.
        /// </summary>
        public static readonly IReadOnlyDictionary<string, string> KnownProfileBackedDispatchLNs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["0.5.25.9.0.255"] = "1.0.99.1.0.255", // Load Survey / Block Load
            ["0.6.25.9.0.255"] = "1.0.99.2.0.255", // Daily
            ["0.7.25.9.0.255"] = "1.0.98.1.0.255", // Billing
        };

        /// <summary>OBIS of the Instantaneous push dispatch channel — no profile buffer backs it.</summary>
        public const string InstantDispatchLN = "0.0.25.9.0.255";

        /// <summary>
        /// Builds a push directly from this meter's own pull data when the template has no
        /// PushSetup object for the requested dispatch LN — the meter should be able to push
        /// anything it can already answer on pull, without requiring a template author to
        /// separately hand-author a PushSetup for every profile. Returns null for a dispatch LN this
        /// isn't confident about (an unrecognized OBIS, or Events — its dispatch is a set of several
        /// category codes with no single owning profile, so there is no safe default here) or when
        /// the underlying data isn't actually present in this template.
        /// </summary>
        private GXDLMSPushSetup? BuildEphemeralPushSetup(string dispatchLogicalName)
        {
            if (dispatchLogicalName == InstantDispatchLN)
            {
                return BuildEphemeralInstantPushSetup();
            }

            if (KnownProfileBackedDispatchLNs.TryGetValue(dispatchLogicalName, out string? sourceProfileLn))
            {
                return BuildEphemeralProfileBackedPushSetup(dispatchLogicalName, sourceProfileLn);
            }

            return null;
        }

        /// <summary>
        /// Device ID, SelfLN, the dedicated profile-backed RTC clock, then the source profile's own
        /// CaptureObjects (skipping its own clock column) — the exact same shape a hand-authored
        /// PushSetup uses (see SA1231166HP_values.xml's Block Load Push Setup), just assembled at
        /// send time instead of declared in the template. Never registered in any collection —
        /// GeneratePushSetupMessages only ever reads the object references it's handed directly.
        /// </summary>
        private GXDLMSPushSetup? BuildEphemeralProfileBackedPushSetup(string dispatchLogicalName, string sourceProfileLn)
        {
            if (_objectsFromFile.FindByLN(ObjectType.ProfileGeneric, sourceProfileLn) is not GXDLMSProfileGeneric profile
                || profile.Buffer.Count == 0 || profile.CaptureObjects.Count == 0)
            {
                return null;
            }

            var push = new GXDLMSPushSetup(dispatchLogicalName);
            AddDeviceIdAndSelfLN(push);
            push.PushObjectList.Add(new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(
                new GXDLMSClock(ProfileBackedPushRtcLN), new GXDLMSCaptureObject(2, 0)));

            // Column 0 of every row is the profile's own clock column, already covered above by the
            // dedicated RTC slot — everything after it is the actual captured data.
            for (int i = 1; i < profile.CaptureObjects.Count; i++)
            {
                var (obj, capture) = (profile.CaptureObjects[i].Key, profile.CaptureObjects[i].Value);
                push.PushObjectList.Add(new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(obj, capture));
            }

            CoreLog.Debug($"[Push] {_meter.MeterNo}: built ephemeral push for {dispatchLogicalName} from {sourceProfileLn} (no PushSetup declared in this template)");
            return push;
        }

        /// <summary>
        /// Device ID, SelfLN, the ordinary "now" clock, then every scalar Register/Data this meter
        /// exposes — mirrors the same fallback <c>MeterDataSnapshotReader</c> already uses to show an
        /// Instantaneous view when a template has no dedicated Instant PushSetup either.
        /// </summary>
        private GXDLMSPushSetup BuildEphemeralInstantPushSetup()
        {
            var push = new GXDLMSPushSetup(InstantDispatchLN);
            AddDeviceIdAndSelfLN(push);
            push.PushObjectList.Add(new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(
                new GXDLMSClock("0.0.1.0.0.255"), new GXDLMSCaptureObject(2, 0)));

            foreach (GXDLMSObject obj in _objectsFromFile
                .Where(o => o is GXDLMSRegister or GXDLMSData)
                .OrderBy(o => o.LogicalName, StringComparer.Ordinal))
            {
                push.PushObjectList.Add(new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(obj, new GXDLMSCaptureObject(2, 0)));
            }

            CoreLog.Debug($"[Push] {_meter.MeterNo}: built ephemeral Instantaneous push (no PushSetup declared in this template)");
            return push;
        }

        private void AddDeviceIdAndSelfLN(GXDLMSPushSetup push)
        {
            if (_objectsFromFile.FindByLN(ObjectType.Data, DeviceIdLN) is GXDLMSData deviceId)
            {
                push.PushObjectList.Add(new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(deviceId, new GXDLMSCaptureObject(2, 0)));
            }

            push.PushObjectList.Add(new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(push, new GXDLMSCaptureObject(1, 0)));
        }

        /// <summary>
        /// How stale the Block Load buffer's newest row is allowed to get before it is re-shifted
        /// forward — one capture period, so a buffer that is still within its own cadence of "now"
        /// is left untouched (the common case: nothing to do on almost every push).
        /// </summary>
        private static readonly TimeSpan BlockLoadFreshnessTolerance = TimeSpan.FromMinutes(30);

        /// <summary>
        /// <see cref="MeterObjectLoader.ShiftBufferTimestamps"/> rolls the Block Load buffer forward
        /// to "now" exactly once, at template load. The template model is cached and shared for the
        /// whole process lifetime (see <see cref="TemplateModelCache"/>), and a meter's session is
        /// built once and never rebuilt (see <see cref="ManyMeterSimulator.Brain.MeterSessionManager"/>),
        /// so without this, the buffer's "latest" row falls further and further behind real time the
        /// longer the process stays up — every push (and every HES pull of this same shared profile)
        /// after that reports an increasingly stale RTC, frozen at whenever the template first loaded.
        ///
        /// <para>
        /// Re-applies the same shift whenever the buffer has drifted more than one capture period
        /// behind now, so "newest row ≈ now" stays true regardless of how long the process has run or
        /// how the push was triggered. Mutates the SHARED profile buffer (every meter on this template
        /// reads the same one), so pull-path reads stay consistent with what gets pushed — and that
        /// mutation is guarded by <see cref="PushEncodeLock"/> since concurrent pushes for other
        /// meters on the same template can race here.
        /// </para>
        /// </summary>
        private static void EnsureBufferFreshness(GXDLMSProfileGeneric profile)
        {
            DateTimeOffset? latest = MeterObjectLoader.LatestConcreteTimestamp(profile);
            if (latest is null || DateTimeOffset.UtcNow - latest.Value <= BlockLoadFreshnessTolerance)
            {
                return;
            }

            lock (PushEncodeLock)
            {
                // Re-check inside the lock: another meter on this shared template may have already
                // refreshed the buffer while this thread was waiting for the lock.
                latest = MeterObjectLoader.LatestConcreteTimestamp(profile);
                TimeSpan staleness = DateTimeOffset.UtcNow - (latest ?? DateTimeOffset.UtcNow);
                if (latest is null || staleness <= BlockLoadFreshnessTolerance)
                {
                    return;
                }

                int shifted = MeterObjectLoader.ShiftProfileTimestamps(profile, staleness);
                CoreLog.Debug(
                    $"[Push] {profile.LogicalName}: buffer was {staleness.TotalMinutes:F0}m stale, " +
                    $"re-shifted {shifted} timestamp(s) forward");
            }
        }

        /// <summary>Rounds to the nearest multiple of <paramref name="period"/>, half-up on an exact tie.</summary>
        private static DateTime RoundToNearestPeriod(DateTime value, TimeSpan period)
        {
            long blockTicks = period.Ticks;
            long remainder = value.Ticks % blockTicks;
            long rounded = remainder < blockTicks / 2 ? value.Ticks - remainder : value.Ticks + (blockTicks - remainder);
            return new DateTime(rounded, value.Kind);
        }

        /// <summary>
        /// The DataNotification encoder for this meter, built on first use. Callers are already
        /// inside <see cref="PushEncodeLock"/>, so no additional synchronisation is needed here.
        /// Meter is the source (server address); the client/HES is the destination address.
        /// </summary>
        private GXDLMSSecureNotify Notify =>
            _notify ??= new GXDLMSSecureNotify(
                true, _meter.ClientAddress, _meter.ServerAddress, InterfaceType.WRAPPER);

        /// <summary>
        /// Applies plaintext or glo-ciphering to the notify encoder.
        ///
        /// <para>
        /// Security.Encryption (confidentiality only, no auth tag) — NOT AuthenticationEncryption —
        /// to match the HES receiver, which is configured the same way
        /// (<c>clientState.Client.Ciphering.Security = Security.Encryption</c>). A mismatch here
        /// produces a security-control byte / GCM tag length the HES does not expect and it fails
        /// to decrypt.
        /// </para>
        /// </summary>
        private void ConfigureNotifyCiphering(bool useCiphering)
        {
            if (useCiphering)
            {
                Notify.Ciphering.Security = Security.Encryption;
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
