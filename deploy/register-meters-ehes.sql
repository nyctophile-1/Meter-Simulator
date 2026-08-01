/*==============================================================================
  Register simulated meters into the eHES database (PostgreSQL).

  Loads the batch CSV exported from the simulator UI, then inserts into the three
  registration tables: meter_nameplate, meter_security, meter_routing.

  NODEID CONVENTION: nodeid is the numeric part of the meter number, matching how
  real meters are registered here (AS9003699 -> 9003699, SZ0020050 -> 20050).
  Serials are 'MY' + 9-digit index, so nodeid = the batch index itself.
      MY000000216 -> nodeid 216

  SKIP RULE: a meter is inserted into ALL THREE tables or NONE. If its nodeid is
  already present in any of the three, or its serial is already in meter_nameplate,
  it is silently skipped and the run continues. Re-running is therefore safe.

  CLEAN SLATE: prompts Y/N on start. Y deletes every previously registered
  simulator meter (meternumber LIKE 'MY%') from all three tables first, in
  dependency order routing -> security -> nameplate, then re-inserts. Use this
  after changing the meter prefix, so stale rows pointing at a dead server are
  replaced rather than skipped.

  Run (set the CSV path in the \copy line below first):
    psql -h HOST -U USER -d DB -f deploy/register-meters-ehes.sql

  The insert is one transaction. To dry-run, change the final COMMIT to ROLLBACK.
==============================================================================*/

\set ON_ERROR_STOP on
\timing on

\prompt 'Clean slate? Deletes ALL existing MY% sim meters first (Y/N): ' clean_in

-- ── Staging: the CSV exactly as the simulator exports it ─────────────────────
-- Columns: index, serial, ipv6, port, template
DROP TABLE IF EXISTS meter_import;
CREATE TEMP TABLE meter_import (
    idx      bigint,
    serial   text,
    ipv6     text,
    port     int,
    template text
);

-- ◄── CSV PATH: edit this line for a different batch export. Forward slashes.
--     Hardcoded rather than passed with -v, because psql does not reliably
--     interpolate :'variables' inside \copy.
\copy meter_import (idx, serial, ipv6, port, template) FROM 'C:/Users/ayush/Downloads/batch-mainB-meters.csv' WITH (FORMAT csv, HEADER true)

SELECT count(*) AS staged_rows, min(idx) AS first_idx, max(idx) AS last_idx FROM meter_import;

BEGIN;

-- ══════════════════════ PARAMETERS ══════════════════════
--   projectid       eHES project the meters belong to
--   metertemplateid eHES object model (must match the simulator's DLMS template)
CREATE OR REPLACE TEMP VIEW p AS
SELECT 1::int  AS projectid,
       31::int AS metertemplateid;

-- ══════════════════════ CLEAN SLATE (optional) ══════════════════════
-- Dependency order mirrors DeleteNameplate.sql: routing, then security, then
-- nameplate. Scoped to 'MY%' serials, which only the simulator uses - no real
-- meter in this database is touched.
SELECT lower(trim(:'clean_in')) IN ('y','yes') AS do_clean \gset

\if :do_clean
\echo '>>> CLEAN SLATE: deleting existing MY% sim meters'
DELETE FROM meter_routing   WHERE meternumber LIKE 'MY%';
DELETE FROM meter_security  WHERE meternumber LIKE 'MY%';
DELETE FROM meter_nameplate WHERE meternumber LIKE 'MY%';
\else
\echo '>>> Keeping existing sim meters; already-registered ones will be skipped'
\endif

-- ── Eligible set, decided once ───────────────────────────────────────────────
-- Anything already known to eHES (by nodeid in any of the three tables, or by
-- serial in the nameplate) drops out here, so the three inserts below can never
-- disagree about which meters they are writing. Real meters already holding a
-- nodeid in the batch's index range are protected by this and simply skipped.
CREATE TEMP TABLE to_insert ON COMMIT DROP AS
SELECT m.idx,
       m.serial,
       m.ipv6,
       m.port,
       m.idx::varchar AS nodeid,      -- numeric part of the meter number
       p.projectid,
       p.metertemplateid
FROM   meter_import m
CROSS  JOIN p
WHERE  NOT EXISTS (SELECT 1 FROM meter_nameplate n WHERE n.nodeid      = m.idx::varchar)
  AND  NOT EXISTS (SELECT 1 FROM meter_security  s WHERE s.nodeid      = m.idx::varchar)
  AND  NOT EXISTS (SELECT 1 FROM meter_routing   r WHERE r.nodeid      = m.idx::varchar)
  AND  NOT EXISTS (SELECT 1 FROM meter_nameplate n WHERE n.meternumber = m.serial);

SELECT count(*) AS will_insert,
       (SELECT count(*) FROM meter_import) - count(*) AS will_skip
FROM   to_insert;

-- ── 1. Nameplate ─────────────────────────────────────────────────────────────
INSERT INTO meter_nameplate
 (projectid, nodeid, meternumber, deviceid, manufacturer, firmwareversion, metertype,
  metercategory, rating, yearofmanufacture, ctratio, ptratio, rfversion, satno,
  createdat, installedat, originalinstalledat, metertemplateid, tcpip, port,
  communicationtype, gatewayid, expectedblockloadcounts, expectedinstantcounts,
  isactive, meteruuid, ageingindays, driftinseconds)
SELECT t.projectid, t.nodeid, t.serial, 'CRY000' || t.serial,
       'Kushal (Kimbal)', 'CRY 13.00', '6', 'D1', '(10-60)A', 2025, 1, 1, '11.11.0.5', 'NONSAT',
       now(), now(), now(), t.metertemplateid, t.ipv6, t.port::varchar,
       'TCP', 'direct_tcp', 48, 48, true, t.serial, 0, 0
FROM   to_insert t;

-- ── 2. Security ──────────────────────────────────────────────────────────────
-- One shared DLMS identity across the whole fleet; only the serial differs.
-- These values must match the simulator, not eHES convention.
INSERT INTO meter_security
 (nodeid, projectid, masterkey, globalkey, hlsussecret, hlsfwsecret, llsmrsecret,
  meternumber, "GlobalAuthenticationKey", "UnicastEncryptionKey")
SELECT t.nodeid, t.projectid,
       'AAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAA','12345678',
       t.serial, 'AAAAAAAAAAAAAAAA','AAAAAAAAAAAAAAAA'
FROM   to_insert t;

-- ── 3. Routing ───────────────────────────────────────────────────────────────
INSERT INTO meter_routing
 (projectid, yearmonthdayist, nodeid, createddateist, createddateutc, gatewayid,
  sinkid, linkscore, lastcommunicatedon, sourceendpoint, hopcount, meternumber)
SELECT t.projectid, to_char(now() AT TIME ZONE 'Asia/Kolkata','YYYYMMDD')::bigint,
       t.nodeid, now() AT TIME ZONE 'Asia/Kolkata', now(),
       'direct_tcp', 'direct_tcp', 1, now(), 1, 1, t.serial
FROM   to_insert t;

COMMIT;   -- ◄── change to ROLLBACK for a dry run

-- ── Verification ─────────────────────────────────────────────────────────────
-- All three counts must be identical, and the orphan counts must be zero.
SELECT (SELECT count(*) FROM meter_nameplate WHERE meternumber LIKE 'MY%') AS nameplate,
       (SELECT count(*) FROM meter_security  WHERE meternumber LIKE 'MY%') AS security,
       (SELECT count(*) FROM meter_routing   WHERE meternumber LIKE 'MY%') AS routing;

SELECT n.meternumber, n.nodeid, n.tcpip, n.port, n.metertemplateid, n.metertype,
       n.metercategory, n.communicationtype, s.globalkey, r.sinkid
FROM   meter_nameplate n
LEFT   JOIN meter_security s ON s.nodeid = n.nodeid AND s.projectid = n.projectid
LEFT   JOIN meter_routing  r ON r.nodeid = n.nodeid AND r.projectid = n.projectid
WHERE  n.meternumber LIKE 'MY%'
ORDER  BY n.meternumber
LIMIT  10;

-- ── Export the fully-registered meters ───────────────────────────────────────
-- Only meters from THIS batch (joined back to the staged CSV) that ended up in
-- all three tables. Meters that were skipped - because a real meter already held
-- their nodeid - are excluded, so this file is the authoritative list to hand to
-- the HES. EXISTS rather than JOIN, so a duplicate row downstream cannot inflate
-- the output.
\echo '>>> Exporting fully-registered meters'

SELECT count(*) AS exporting
FROM   meter_nameplate n
WHERE  EXISTS (SELECT 1 FROM meter_import  m WHERE m.serial = n.meternumber)
  AND  EXISTS (SELECT 1 FROM meter_security s WHERE s.nodeid = n.nodeid)
  AND  EXISTS (SELECT 1 FROM meter_routing  r WHERE r.nodeid = n.nodeid);

-- ◄── OUTPUT PATH: edit if you want the file somewhere else. Forward slashes.
\copy (SELECT n.meternumber, n.nodeid, n.tcpip, n.port, n.metertemplateid, n.metertype, n.metercategory, n.communicationtype FROM meter_nameplate n WHERE EXISTS (SELECT 1 FROM meter_import m WHERE m.serial = n.meternumber) AND EXISTS (SELECT 1 FROM meter_security s WHERE s.nodeid = n.nodeid) AND EXISTS (SELECT 1 FROM meter_routing r WHERE r.nodeid = n.nodeid) ORDER BY n.meternumber) TO 'C:/Users/ayush/Downloads/valid-sim-meters.csv' WITH (FORMAT csv, HEADER true)

\echo '>>> Written: C:/Users/ayush/Downloads/valid-sim-meters.csv'
