<#
    load-meters.ps1
    Bulk-loads all-meters.csv into public.meter_nameplate.

    Rows are skipped (not failed) when the csv's own nodeid already exists in the
    table, or the meternumber already exists. Skipped rows are written out to
    skipped-meters.csv next to the input file.

    Requires psql (PostgreSQL client) on PATH.
    If you don't have it:  winget install PostgreSQL.PostgreSQL.17

    Run:  powershell -ExecutionPolicy Bypass -File .\load-meters.ps1
#>

# ==================== EDIT THESE ====================
$PGHOST     = "52.66.27.228"
$PGPORT     = "5432"
$PGDATABASE = "ehesdev"
$PGUSER     = "ehesqa_user"
# Supply this once per session: $env:EHES_SQL_PASSWORD = '<password>'
# If omitted, the script asks for it without displaying the value.
$PGPASSWORD = $env:EHES_SQL_PASSWORD
$PGSSLMODE  = "prefer"           # your TablePlus profile has TLS off; "prefer" tries SSL, falls back

$CSV        = "C:\Users\ayush\Downloads\all-meters.csv"
$BATCH      = 50000              # rows per commit
$PROJECTID  = 1
$TEMPLATEID = 111                # metertemplateid  (integer)
$CATEGORY   = "D1"               # metercategory    (D1, D2 or D3)
$METERTYPE  = "6"                # metertype        (6, 7, 8 or 10)
# ====================================================

if ($CATEGORY -notin @("D1","D2","D3")) { throw "CATEGORY must be D1, D2 or D3 (got '$CATEGORY')." }
if ($METERTYPE -notin @("6","7","8","10")) { throw "METERTYPE must be 6, 7, 8 or 10 (got '$METERTYPE')." }
if (-not ($TEMPLATEID -is [int])) { throw "TEMPLATEID must be an integer (got '$TEMPLATEID')." }

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($PGPASSWORD)) {
    $securePassword = Read-Host "Password for $PGUSER@$PGHOST" -AsSecureString
    $PGPASSWORD = [System.Net.NetworkCredential]::new('', $securePassword).Password
}

# --- preflight ---
if (-not (Get-Command psql -ErrorAction SilentlyContinue)) {
    $guess = Get-ChildItem "C:\Program Files\PostgreSQL\*\bin\psql.exe" -EA SilentlyContinue |
             Sort-Object FullName -Descending | Select-Object -First 1
    if ($guess) { $env:Path = "$($guess.Directory);$env:Path"; Write-Host "Using $($guess.FullName)" }
    else { throw "psql not found on PATH. Install the PostgreSQL client, then re-run." }
}
if (-not (Test-Path $CSV)) { throw "CSV not found: $CSV" }

$SKIPCSV     = Join-Path (Split-Path $CSV -Parent) "skipped-meters.csv"
$csvForCopy  = ($CSV     -replace '\\', '/')
$skipForCopy = ($SKIPCSV -replace '\\', '/')

Write-Host "CSV     : $CSV  ($([math]::Round((Get-Item $CSV).Length/1MB,1)) MB)"
Write-Host "Skipped : $SKIPCSV"
Write-Host "DB      : $PGUSER@$PGHOST`:$PGPORT/$PGDATABASE`n"

$env:PGPASSWORD       = $PGPASSWORD
$env:PGSSLMODE        = $PGSSLMODE
$env:PGCLIENTENCODING = "UTF8"

# --- the whole job as one SQL script ---
$sql = @'
\set ON_ERROR_STOP on
\timing on

-- 1. staging table -----------------------------------------------------------
DROP TABLE IF EXISTS stg_meters;
DROP TABLE IF EXISTS stg_skipped;

CREATE UNLOGGED TABLE stg_meters (
    idx      bigint PRIMARY KEY,
    nodeid   text,
    serial   text,
    nic      text,
    ipv6     text,
    port     text,
    template text,
    batch    text,
    deviceid text
);

-- 2. load the csv (client-side, streams over the connection) ------------------
-- column order must match all-meters.csv: index,nodeid,serial,nic,ipv6,port,template,batch
\echo '>> copying csv ...'
\copy stg_meters (idx, nodeid, serial, nic, ipv6, port, template, batch) FROM '__CSVPATH__' WITH (FORMAT csv, HEADER true)

-- 3. derive deviceid once, up front (nodeid comes straight from the csv) ------
\echo '>> deriving deviceid ...'
UPDATE stg_meters
SET deviceid = 'MAYA00' || regexp_replace(serial,'[^0-9]','','g');

CREATE INDEX stg_meters_nodeid_idx ON stg_meters (nodeid);
CREATE INDEX stg_meters_serial_idx ON stg_meters (serial);
ANALYZE stg_meters;

-- 4. quarantine anything that would collide ----------------------------------
\echo '>> checking collisions ...'
CREATE UNLOGGED TABLE stg_skipped (
    idx      bigint,
    serial   text,
    nodeid   text,
    ipv6     text,
    reason   text
);

-- 4a. nodeid already present in the target table
INSERT INTO stg_skipped (idx, serial, nodeid, ipv6, reason)
SELECT s.idx, s.serial, s.nodeid, s.ipv6, 'nodeid already exists in meter_nameplate'
FROM stg_meters s
WHERE EXISTS (SELECT 1 FROM public.meter_nameplate m WHERE m.nodeid = s.nodeid);

-- 4b. meternumber already present in the target table
INSERT INTO stg_skipped (idx, serial, nodeid, ipv6, reason)
SELECT s.idx, s.serial, s.nodeid, s.ipv6, 'meternumber already exists in meter_nameplate'
FROM stg_meters s
WHERE EXISTS (SELECT 1 FROM public.meter_nameplate m WHERE m.meternumber = s.serial)
  AND NOT EXISTS (SELECT 1 FROM stg_skipped k WHERE k.idx = s.idx);

-- 4c. duplicate nodeid inside the csv itself (keeps the lowest idx)
INSERT INTO stg_skipped (idx, serial, nodeid, ipv6, reason)
SELECT s.idx, s.serial, s.nodeid, s.ipv6, 'duplicate nodeid within the csv'
FROM stg_meters s
WHERE EXISTS (SELECT 1 FROM stg_meters t WHERE t.nodeid = s.nodeid AND t.idx < s.idx)
  AND NOT EXISTS (SELECT 1 FROM stg_skipped k WHERE k.idx = s.idx);

CREATE INDEX stg_skipped_idx_idx ON stg_skipped (idx);
DELETE FROM stg_meters s WHERE EXISTS (SELECT 1 FROM stg_skipped k WHERE k.idx = s.idx);
ANALYZE stg_meters;

\echo '>> collision summary:'
SELECT reason, count(*) AS rows_skipped FROM stg_skipped GROUP BY reason ORDER BY 2 DESC;
SELECT count(*) AS rows_to_insert FROM stg_meters;

-- 5. make sure the pk sequence is ahead of max(nameplateid) -------------------
SELECT setval('public.meter_nameplate_nameplateid_seq',
              GREATEST((SELECT COALESCE(max(nameplateid),1) FROM public.meter_nameplate),
                       (SELECT last_value FROM public.meter_nameplate_nameplateid_seq)));

-- 6. batched insert, one commit per batch, safe to re-run ---------------------
CREATE OR REPLACE PROCEDURE public.load_meter_batch(p_step bigint)
LANGUAGE plpgsql AS $proc$
DECLARE
    v_lo bigint; v_max bigint; v_n bigint; v_total bigint := 0;
    v_ts timestamptz := now();
BEGIN
    SELECT COALESCE(min(idx),0), COALESCE(max(idx),-1) INTO v_lo, v_max FROM stg_meters;

    WHILE v_lo <= v_max LOOP
        INSERT INTO public.meter_nameplate (
            projectid, nodeid, meternumber, ageingindays, communicationtype, createdat,
            ctratio, deviceid, driftinseconds, firmwareversion, firstcommunicationat,
            installedat, latitude, longitude, manufacturer, metercategory,
            meterclockdatetime, meterclocksynctime, metertemplateid, metertype,
            originalinstalledat, ptratio, rating, rfversion, satcompletionat, satno,
            yearofmanufacture, expectedblockloadcounts, gatewayid, expectedinstantcounts,
            satrealizationtime, migratedat, tcpip, port, meterconnectionstatusupdatedat,
            meterrcdcstatus, meterconnectionstatus, isactive, meteruuid
        )
        SELECT
            __PROJECTID__,          -- projectid
            s.nodeid,               -- nodeid            101
            s.serial,               -- meternumber       MY000000101
            0,                      -- ageingindays
            'TCP',                  -- communicationtype
            v_ts,                   -- createdat
            1,                      -- ctratio
            s.deviceid,             -- deviceid          MAYA00000000101
            0,                      -- driftinseconds
            'AGXX01',               -- firmwareversion
            v_ts,                   -- firstcommunicationat
            v_ts,                   -- installedat
            '',                     -- latitude
            '',                     -- longitude
            'Kushal (Kimbal)',      -- manufacturer
            '__CATEGORY__',         -- metercategory
            v_ts,                   -- meterclockdatetime
            v_ts,                   -- meterclocksynctime
            __TEMPLATEID__,         -- metertemplateid
            '__METERTYPE__',        -- metertype
            v_ts,                   -- originalinstalledat
            1,                      -- ptratio
            '(10-60)A',             -- rating
            '11.11.0.5',            -- rfversion
            NULL::timestamptz,      -- satcompletionat
            'NONSAT',               -- satno
            2025,                   -- yearofmanufacture
            48,                     -- expectedblockloadcounts
            '',                     -- gatewayid
            48,                     -- expectedinstantcounts
            NULL::timestamptz,      -- satrealizationtime
            v_ts,                   -- migratedat
            s.ipv6,                 -- tcpip
            '4059',                 -- port (varchar)
            (v_ts AT TIME ZONE 'UTC'),  -- meterconnectionstatusupdatedat
            2,                      -- meterrcdcstatus
            'true',                 -- meterconnectionstatus
            true,                   -- isactive
            s.serial                -- meteruuid
        FROM stg_meters s
        WHERE s.idx >= v_lo AND s.idx < v_lo + p_step
        ON CONFLICT (meternumber) DO NOTHING;   -- safety net for concurrent writers

        GET DIAGNOSTICS v_n = ROW_COUNT;
        v_total := v_total + v_n;
        COMMIT;

        RAISE NOTICE 'idx % .. %  | +% rows | total %', v_lo, v_lo + p_step - 1, v_n, v_total;
        v_lo := v_lo + p_step;
    END LOOP;

    RAISE NOTICE 'done. inserted % rows', v_total;
END
$proc$;

\echo '>> inserting ...'
CALL public.load_meter_batch(__BATCH__);

-- 7. verify -------------------------------------------------------------------
SELECT count(*) AS total_rows_now FROM public.meter_nameplate;

SELECT nameplateid, nodeid, meternumber, deviceid, tcpip, port, metertemplateid, createdat
FROM public.meter_nameplate
WHERE meternumber LIKE 'MY%'
ORDER BY nameplateid DESC
LIMIT 5;

-- nodeid should still be unique across the whole table
SELECT count(*) AS duplicate_nodeids_remaining
FROM (SELECT nodeid FROM public.meter_nameplate GROUP BY nodeid HAVING count(*) > 1) d;

-- 8. write skipped rows out, then clean up ------------------------------------
\echo '>> writing skipped rows ...'
\copy (SELECT idx, serial, nodeid, ipv6, reason FROM stg_skipped ORDER BY idx) TO '__SKIPPATH__' WITH (FORMAT csv, HEADER true)

DROP TABLE IF EXISTS stg_meters;
DROP TABLE IF EXISTS stg_skipped;
DROP PROCEDURE IF EXISTS public.load_meter_batch(bigint);
'@

$sql = $sql.Replace('__CSVPATH__',    $csvForCopy).
            Replace('__SKIPPATH__',   $skipForCopy).
            Replace('__BATCH__',      "$BATCH").
            Replace('__PROJECTID__',  "$PROJECTID").
            Replace('__TEMPLATEID__', "$TEMPLATEID").
            Replace('__CATEGORY__',   $CATEGORY).
            Replace('__METERTYPE__',  $METERTYPE)

$tmp = Join-Path $env:TEMP "load-meters-$(Get-Date -f yyyyMMdd-HHmmss).sql"
[System.IO.File]::WriteAllText($tmp, $sql, (New-Object System.Text.UTF8Encoding $false))

$started = Get-Date
psql -h $PGHOST -p $PGPORT -d $PGDATABASE -U $PGUSER -v ON_ERROR_STOP=1 -f $tmp
$code = $LASTEXITCODE

Remove-Item $tmp -Force -EA SilentlyContinue
$env:PGPASSWORD = $null

$mins = [math]::Round(((Get-Date) - $started).TotalMinutes, 1)
if ($code -eq 0) {
    Write-Host "`nOK - finished in $mins min." -ForegroundColor Green
    if (Test-Path $SKIPCSV) { Write-Host "Skipped rows listed in: $SKIPCSV" -ForegroundColor Yellow }
} else {
    Write-Host "`nFAILED (psql exit $code) after $mins min. Re-run - rows already inserted are skipped." -ForegroundColor Red
}
exit $code
