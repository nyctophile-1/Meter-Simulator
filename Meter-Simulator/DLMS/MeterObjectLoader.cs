using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Objects.Enums;
using System;
using System.Collections.Generic;
using System.Linq;

namespace MeterSimulator.DLMS
{
    public class MeterObjectLoader
    {
        private readonly string _xmlPath;

        public MeterObjectLoader(string xmlPath)
        {
            _xmlPath = xmlPath;
        }

        // ════════════════════════════════════════════════════════════════════════
        // PUBLIC ENTRY POINT
        // ════════════════════════════════════════════════════════════════════════
        public void Load(GXDLMSObjectCollection target)
        {
            // Step 1 ── Raw load from XML
            // Gurux reconstructs every object but may create multiple instances of
            // the same LN (one full definition + several lightweight stubs inside
            // each Association's ObjectList).
            GXDLMSObjectCollection raw = GXDLMSObjectCollection.Load(_xmlPath);
            Console.WriteLine($"[Loader] Raw XML loaded: {raw.Count} objects");

            // Step 2 ── Deduplicate
            // For each (ObjectType, LN) pair keep only the richest instance so that
            // every subsequent FindByLN call returns the real object, not a stub.
            //   • ProfileGeneric  → keep the one with the most CaptureObjects
            //   • Everything else → keep the first occurrence (full definition
            //     always appears before association stubs in Gurux XML exports)
            GXDLMSObjectCollection objects = Deduplicate(raw);
            Console.WriteLine($"[Loader] After dedup: {objects.Count} objects");

            // Step 3 ── Internal CaptureObject rewire
            // The XML deserializer creates brand-new stub instances for each
            // CaptureObject reference instead of pointing at the objects already
            // in the collection.  Replace every CaptureObject key with the
            // canonical instance from the deduplicated collection so that when
            // Items.Add(obj) runs in DLMSServerSession the CaptureObject
            // references ARE the Items instances — no second pass needed.
            RewireCaptureObjects(objects);

            // Step 4 ── Seed live values (registers, clock, data — NOT profile buffers)
            // Profile buffer rows come from the XML as-is.
            SeedClock(objects);
            SeedRegisters(objects);
            //SeedDataObjects(objects);
            LogProfiles(objects);   // just prints what the XML gave us

            // Step 5 ── Hand off
            target.AddRange(objects);
        }

        // ════════════════════════════════════════════════════════════════════════
        // STEP 2 — DEDUPLICATE
        // ════════════════════════════════════════════════════════════════════════
        private static GXDLMSObjectCollection Deduplicate(GXDLMSObjectCollection raw)
        {
            var result = new GXDLMSObjectCollection();

            // Group by the natural key Gurux uses: ObjectType + LogicalName
            var groups = raw
                .GroupBy(o => $"{(int)o.ObjectType}:{o.LogicalName}");

            foreach (var group in groups)
            {
                GXDLMSObject best;

                // For ProfileGeneric, prefer the instance with the most CaptureObjects
                // (that is the full definition, not an association stub).
                var profiles = group.OfType<GXDLMSProfileGeneric>().ToList();
                if (profiles.Count > 0)
                {
                    best = profiles.OrderByDescending(p => p.CaptureObjects.Count).First();
                }
                else
                {
                    // For all other types, the first instance is the full definition.
                    best = group.First();
                }

                Console.WriteLine($"[Dedup] Kept {best.ObjectType} {best.LogicalName}" +
                    (best is GXDLMSProfileGeneric pg
                        ? $" ({pg.CaptureObjects.Count} capture cols, {group.Count()} duplicates in XML)"
                        : $" ({group.Count()} duplicates in XML)"));

                result.Add(best);
            }

            return result;
        }

        // ════════════════════════════════════════════════════════════════════════
        // STEP 3 — INTERNAL CAPTUРЕOBJECT REWIRE
        // After dedup there is exactly one canonical instance per (ObjectType, LN).
        // Each profile's CaptureObject keys still point to the XML-deserialized
        // stubs.  Replace them with the canonical instances from `objects` so
        // the references survive the Items.Add call in DLMSServerSession.
        // ════════════════════════════════════════════════════════════════════════
        private static void RewireCaptureObjects(GXDLMSObjectCollection objects)
        {
            foreach (var profile in objects.OfType<GXDLMSProfileGeneric>().ToList())
            {
                if (profile.CaptureObjects.Count == 0) continue;

                var rewired = new List<GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>>();

                foreach (var kv in profile.CaptureObjects)
                {
                    // Look for the canonical instance in the deduped collection
                    var canonical = objects.FindByLN(kv.Key.ObjectType, kv.Key.LogicalName);

                    if (canonical == null)
                    {
                        // Object referenced by CaptureObjects but not present as a
                        // top-level object in the XML — add the stub itself so Gurux
                        // can at least resolve its DataType during encoding.
                        Console.WriteLine($"  [Rewire] WARNING: {kv.Key.ObjectType} " +
                            $"{kv.Key.LogicalName} not found — registering stub");
                        objects.Add(kv.Key);
                        canonical = kv.Key;
                    }

                    rewired.Add(new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(
                        canonical, kv.Value));
                }

                profile.CaptureObjects.Clear();
                profile.CaptureObjects.AddRange(rewired);

                Console.WriteLine($"[Rewire] {profile.LogicalName}: " +
                    $"{rewired.Count} capture columns wired to canonical instances");
            }
        }

        // ════════════════════════════════════════════════════════════════════════
        // STEP 4a — CLOCK
        // ════════════════════════════════════════════════════════════════════════
        private static void SeedClock(GXDLMSObjectCollection objects)
        {
            var clock = objects.FindByLN(ObjectType.Clock, "0.0.1.0.0.255") as GXDLMSClock;
            if (clock == null) return;

            clock.Time     = new GXDateTime(DateTime.UtcNow);
            clock.TimeZone = 330;           // IST UTC+5:30
            clock.Deviation = 0;
            clock.Status   = ClockStatus.Ok;
            clock.SetDataType(2, DataType.DateTime);
        }

        // ════════════════════════════════════════════════════════════════════════
        // STEP 4b — REGISTERS
        // Explicit overrides for key registers, then a catch-all sweep for anything
        // still null.  Type-aware defaults prevent silent encoding failures.
        // ════════════════════════════════════════════════════════════════════════
        private static void SeedRegisters(GXDLMSObjectCollection objects)
        {
            var now = DateTime.UtcNow;

            foreach (var obj in objects)
            {
                // NOTE: GXDLMSExtendedRegister inherits GXDLMSRegister.
                // Check the more-specific type FIRST so CaptureTime is also set.
                if (obj is GXDLMSExtendedRegister ext)
                {
                    if (ext.Value == null)
                        ext.Value = DefaultForDataType(ext.GetDataType(2), now);
                    if (ext.CaptureTime == DateTime.MinValue || IsUnspecified(ext.CaptureTime))
                        ext.CaptureTime = now;
                }
                else if (obj is GXDLMSRegister reg && reg.Value == null)
                {
                    reg.Value = DefaultForDataType(reg.GetDataType(2), now);
                }
            }
        }
        private static bool IsUnspecified(GXDateTime dt)
        {
            return dt == null ||
                   dt.Skip.HasFlag(DateTimeSkips.Year) &&
                   dt.Skip.HasFlag(DateTimeSkips.Month) &&
                   dt.Skip.HasFlag(DateTimeSkips.Day) &&
                   dt.Skip.HasFlag(DateTimeSkips.Hour) &&
                   dt.Skip.HasFlag(DateTimeSkips.Minute) &&
                   dt.Skip.HasFlag(DateTimeSkips.Second);
        }
        // ════════════════════════════════════════════════════════════════════════
        // Type-aware default value.
        // Gurux encodes by inspecting the C# runtime type of Value, so returning
        // the wrong type (e.g. int when double is expected) causes silent failures.
        // ════════════════════════════════════════════════════════════════════════
        private static object DefaultForDataType(DataType dt, DateTime now)
        {
            switch (dt)
            {
                case DataType.DateTime:
                case DataType.Date:
                case DataType.Time:     return now;

                case DataType.String:
                case DataType.StringUTF8: return string.Empty;

                case DataType.OctetString: return Array.Empty<byte>();
                case DataType.BitString:   return "0";
                case DataType.Boolean:     return false;

                case DataType.Int8:   return (sbyte)0;
                case DataType.Int16:  return (short)0;
                case DataType.Int32:  return (int)0;
                case DataType.Int64:  return (long)0;

                case DataType.UInt8:  return (byte)0;
                case DataType.UInt16: return (ushort)0;
                case DataType.UInt32: return (uint)0;
                case DataType.UInt64: return (ulong)0;

                case DataType.Float32: return (float)0;
                case DataType.Float64: return (double)0;

                // DataType.None — XML didn't declare a type; use double as safe default
                default: return (double)0;
            }
        }

        // ════════════════════════════════════════════════════════════════════════
        // STEP 4c — DATA OBJECTS
        // ════════════════════════════════════════════════════════════════════════
        private static void SeedDataObjects(GXDLMSObjectCollection objects)
        {
            void Set(string ln, object value, DataType dt = DataType.None)
            {
                var d = objects.FindByLN(ObjectType.Data, ln) as GXDLMSData;
                if (d == null) return;
                if (d.Value == null) d.Value = value;
                if (dt != DataType.None) d.SetDataType(2, dt);
            }

            Set("0.0.96.1.0.255", "HPLSPSM09XX01", DataType.String);  // Serial No
            Set("0.0.96.1.1.255", "HPL",           DataType.String);  // Manufacturer
            Set("0.0.96.1.2.255", "HPL1PMP",       DataType.String);
            Set("0.0.96.1.4.255", "2024",           DataType.String);
            Set("1.0.0.2.0.255",  "V01.00",        DataType.String);  // Firmware

            Set("1.0.0.8.0.255", Convert.ToUInt32(30),    DataType.UInt32); // Demand period
            Set("1.0.0.8.4.255", Convert.ToUInt32(1800),  DataType.UInt32); // Block LP period
            Set("1.0.0.8.5.255", Convert.ToUInt32(86400), DataType.UInt32); // Daily LP period

            Set("0.0.96.2.0.255", Convert.ToUInt32(0), DataType.UInt32);
            Set("0.0.96.7.0.255", Convert.ToUInt32(0), DataType.UInt32);
        }

        // Profile buffers come directly from the XML — no manual seeding.
        // Deduplicate() picks the full definition and RewireCaptureObjects() fixes
        // the instance references.  The buffer rows loaded by Gurux are used as-is.
        private static void LogProfiles(GXDLMSObjectCollection objects)
        {
            foreach (var p in objects.OfType<GXDLMSProfileGeneric>())
                Console.WriteLine($"[Profile] {p.LogicalName}: " +
                    $"{p.CaptureObjects.Count} cols, {p.Buffer.Count} rows, " +
                    $"EntriesInUse={p.EntriesInUse}");
        }
    }
}
