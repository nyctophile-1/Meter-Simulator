using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Objects.Enums;
using System;
using System.Collections.Generic;
using System.Text;

namespace MeterSimulator.DLMS
{
    public class MeterObjectLoader
    {
        private readonly string _xmlPath;

        public MeterObjectLoader(string xmlPath)
        {
            _xmlPath = xmlPath;
        }

        /// <summary>
        /// Deserialize XML → objects, seed values, then copy into <paramref name="target"/>.
        /// </summary>
        public void Load(GXDLMSObjectCollection target)
        {
            // ── Step 1: Gurux built-in XML deserializer ──────────────────────────
            // GXDLMSObjectCollection.Load reads the gxdlmstranslator XML format
            // and reconstructs every GXDLMSData / GXDLMSRegister / GXDLMSProfileGeneric
            // including CaptureObjects wiring inside each ProfileGeneric.
            GXDLMSObjectCollection loaded = GXDLMSObjectCollection.Load(_xmlPath);

            // ── Step 2: Seed live simulation values ──────────────────────────────
            SeedClock(loaded);
            SeedRegisters(loaded);
            SeedDataObjects(loaded);
            SeedProfileBuffers(loaded);

            // ── Step 3: Hand off to the server's _objects collection ─────────────
            target.AddRange(loaded);
        }

        // ════════════════════════════════════════════════════════════════════════
        // CLOCK
        // ════════════════════════════════════════════════════════════════════════
        private static void SeedClock(GXDLMSObjectCollection objects)
        {
            var clock = objects.FindByLN(ObjectType.Clock, "0.0.1.0.0.255") as GXDLMSClock;
            if (clock == null) return;

            clock.Time = new GXDateTime(DateTime.UtcNow);
            clock.TimeZone = 330;          // IST  UTC+5:30
            clock.Deviation = 0;
            clock.Status = ClockStatus.Ok;
            clock.SetDataType(2, DataType.DateTime);
        }

        // ════════════════════════════════════════════════════════════════════════
        // REGISTERS  — set a realistic starting value for every register
        // that came back null from the XML (meter was offline during export).
        // ════════════════════════════════════════════════════════════════════════
        private static void SeedRegisters(GXDLMSObjectCollection objects)
        {
            // Helper: set value only if the XML left it null/zero
            void Set(string ln, object value)
            {
                var r = objects.FindByLN(ObjectType.Register, ln) as GXDLMSRegister;
                if (r != null && (r.Value == null || Convert.ToDouble(r.Value) == 0))
                    r.Value = value;
            }

            // Instantaneous
            Set("1.0.1.7.0.255", 2300.0);   // Active Power W
            Set("1.0.9.7.0.255", 2400.0);   // Apparent Power VA
            Set("1.0.12.7.0.255", 23100.0);  // Voltage  (×0.01 scaler → 231.00 V)
            Set("1.0.11.7.0.255", 10000.0);  // Current  (×0.001 → 10.000 A)
            Set("1.0.91.7.0.255", 100.0);    // Neutral Current
            Set("1.0.13.7.0.255", 950.0);    // Power Factor (×0.001 → 0.950)
            Set("1.0.14.7.0.255", 5000.0);   // Frequency (×0.01 → 50.00 Hz)

            // Cumulative energy totals  (scaler=10 in XML → stored unit is 10 Wh)
            Set("1.0.1.8.0.255", 123400.0); // Wh imp
            Set("1.0.2.8.0.255", 0.0);
            Set("1.0.9.8.0.255", 130000.0); // VAh imp
            Set("1.0.10.8.0.255", 0.0);

            // Reactive quadrants
            Set("1.0.5.8.0.255", 5000.0);
            Set("1.0.6.8.0.255", 0.0);
            Set("1.0.7.8.0.255", 0.0);
            Set("1.0.8.8.0.255", 0.0);

            // TOU slabs 1-8
            for (int t = 1; t <= 8; t++)
            {
                double kwhImp = t == 1 ? 80000.0 : t == 2 ? 43400.0 : 0.0;
                double kvahImp = t == 1 ? 84000.0 : t == 2 ? 46000.0 : 0.0;
                Set($"1.0.1.8.{t}.255", kwhImp);
                Set($"1.0.9.8.{t}.255", kvahImp);
                Set($"1.0.2.8.{t}.255", 0.0);
                Set($"1.0.10.8.{t}.255", 0.0);
            }

            // Block-load averages
            Set("1.0.12.27.0.255", 23100.0);
            Set("1.0.11.27.0.255", 10000.0);
            Set("1.0.91.27.0.255", 100.0);
            Set("1.0.1.29.0.255", 2300.0);
            Set("1.0.9.29.0.255", 2400.0);
            Set("1.0.13.27.0.255", 950.0);

            // Durations
            Set("0.0.94.91.8.255", 23646.0);   // Power Failure Duration
            Set("0.0.94.91.14.255", 8640000.0); // Power On Duration

            // Set data types the server needs for correct encoding
            void SetDt(string ln, DataType dt)
            {
                var r = objects.FindByLN(ObjectType.Register, ln) as GXDLMSRegister;
                r?.SetDataType(2, dt);
            }
            SetDt("1.0.1.8.0.255", DataType.UInt32);
            SetDt("1.0.2.8.0.255", DataType.UInt32);
            SetDt("1.0.9.8.0.255", DataType.UInt32);
            SetDt("1.0.10.8.0.255", DataType.UInt32);
        }

        // ════════════════════════════════════════════════════════════════════════
        // DATA OBJECTS
        // ════════════════════════════════════════════════════════════════════════
        private static void SeedDataObjects(GXDLMSObjectCollection objects)
        {
            void Set(string ln, object value, DataType dt = DataType.None)
            {
                var d = objects.FindByLN(ObjectType.Data, ln) as GXDLMSData;
                if (d == null) return;
                if (d.Value == null)
                    d.Value = value;
                if (dt != DataType.None)
                    d.SetDataType(2, dt);
            }

            Set("0.0.96.1.0.255", "HPLSPSM09XX01", DataType.String);  // Serial No
            Set("0.0.96.1.1.255", "HPL", DataType.String);  // Manufacturer
            Set("0.0.96.1.2.255", "HPL1PMP", DataType.String);
            Set("0.0.96.1.4.255", "2024", DataType.String);
            Set("1.0.0.2.0.255", "V01.00", DataType.String);  // Firmware

            Set("0.0.43.1.3.255", Convert.ToUInt32(207), DataType.UInt32); // Invocation counter

            Set("1.0.0.8.0.255", Convert.ToUInt32(30), DataType.UInt32); // Demand period
            Set("1.0.0.8.4.255", Convert.ToUInt32(1800), DataType.UInt32); // Block LP period
            Set("1.0.0.8.5.255", Convert.ToUInt32(86400), DataType.UInt32); // Daily LP period

            Set("0.0.96.2.0.255", Convert.ToUInt32(0), DataType.UInt32);
            Set("0.0.96.7.0.255", Convert.ToUInt32(0), DataType.UInt32);

            // Invocation counter access
            var ic = objects.FindByLN(ObjectType.Data, "0.0.43.1.3.255") as GXDLMSData;
            ic?.SetAccess(1, AccessMode.Read);
            ic?.SetAccess(2, AccessMode.ReadWrite);
        }

        // ════════════════════════════════════════════════════════════════════════
        // PROFILE BUFFERS
        // The XML exports empty buffers (Buffer node is empty).
        // We seed each profile with realistic historic rows here.
        // ════════════════════════════════════════════════════════════════════════
        private static void SeedProfileBuffers(GXDLMSObjectCollection objects)
        {
            SeedDailyLoadProfile(objects);
            SeedBlockLoadProfile(objects);
            SeedBillingProfile(objects);
        }

        private static void SeedDailyLoadProfile(GXDLMSObjectCollection objects)
        {
            var profile = objects.FindByLN(ObjectType.ProfileGeneric, "1.0.99.2.0.255") as GXDLMSProfileGeneric;
            if (profile == null) return;

            profile.CapturePeriod = 86400;
            profile.ProfileEntries = 365;
            profile.SortMethod = SortMethod.FiFo;

            // The clock is already in CaptureObjects (loaded from XML).
            // Just seed the buffer rows — column count must match CaptureObjects count.
            int cols = profile.CaptureObjects.Count;
            DateTime start = DateTime.UtcNow.Date.AddDays(-30);

            for (int i = 0; i < 30; i++)
            {
                double baseEnergy = 123400.0 - ((30 - i) * 480.0);
                var row = BuildRow(cols, i, new object[]
                {
                    new GXDateTime(start.AddDays(i)),
                    baseEnergy,          // Wh imp total
                    0.0,                 // Wh exp
                    baseEnergy * 1.05,   // VAh imp
                    0.0,                 // VAh exp
                });
                profile.Buffer.Add(row);
            }

            profile.EntriesInUse = (uint)profile.Buffer.Count;
            profile.SetDataType(2, DataType.Structure);
        }

        private static void SeedBlockLoadProfile(GXDLMSObjectCollection objects)
        {
            var profile = objects.FindByLN(ObjectType.ProfileGeneric, "1.0.99.1.0.255") as GXDLMSProfileGeneric;
            if (profile == null) return;

            profile.CapturePeriod = 1800;
            profile.ProfileEntries = 960;
            profile.SortMethod = SortMethod.FiFo;

            int cols = profile.CaptureObjects.Count;
            DateTime start = DateTime.UtcNow.Date.AddDays(-20);

            for (int day = 0; day < 20; day++)
                for (int slot = 0; slot < 48; slot++)
                {
                    var ts = start.AddDays(day).AddMinutes(slot * 30);
                    var row = BuildRow(cols, slot, new object[]
                    {
                    new GXDateTime(ts),
                    23100.0 + (slot % 5),        // V avg
                    10000.0 + (slot * 10),        // I avg
                    100.0,                        // In avg
                    2300.0 + (day * 10),          // W imp avg
                    2400.0 + (day * 10),          // VA imp avg
                    0.0,                          // W exp avg
                    0.0,                          // VA exp avg
                    });
                    profile.Buffer.Add(row);
                }

            profile.EntriesInUse = (uint)profile.Buffer.Count;
            profile.SetDataType(2, DataType.Structure);
        }

        private static void SeedBillingProfile(GXDLMSObjectCollection objects)
        {
            var profile = objects.FindByLN(ObjectType.ProfileGeneric, "1.0.98.1.0.255") as GXDLMSProfileGeneric;
            if (profile == null) return;

            profile.ProfileEntries = 12;
            profile.SortMethod = SortMethod.FiFo;

            int cols = profile.CaptureObjects.Count;
            DateTime billingDate = new DateTime(2026, 4, 17, 17, 0, 0, DateTimeKind.Utc);

            for (int i = 11; i >= 0; i--)
            {
                double energy = 100000.0 + ((11 - i) * 5000.0);
                var row = BuildRow(cols, i, new object[]
                {
                    new GXDateTime(billingDate.AddMonths(-i)),
                    energy,
                    energy * 1.05,
                    energy * 0.65,
                    energy * 0.35,
                });
                profile.Buffer.Add(row);
            }

            profile.EntriesInUse = (uint)profile.Buffer.Count;
            profile.SetDataType(2, DataType.Structure);
        }

        // ════════════════════════════════════════════════════════════════════════
        // HELPER
        // BuildRow: fills a row array of `cols` length with provided seed values.
        // Any column index beyond seed values gets 0 as a safe default.
        // ════════════════════════════════════════════════════════════════════════
        private static object[] BuildRow(int cols, int rowIndex, object[] seed)
        {
            var row = new object[cols];
            for (int c = 0; c < cols; c++)
                row[c] = c < seed.Length ? seed[c] : (object)0;
            return row;
        }
    }
}

