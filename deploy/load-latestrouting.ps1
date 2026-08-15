<#
    load-latestrouting.ps1
    Bulk-loads batch-10-lakh.csv into public.meter_latestrouting.

    Uniqueness enforced on nodeid. Rows that would collide are skipped
    individually and written to skipped-latestrouting.csv next to the input file.

    Requires psql (PostgreSQL client) on PATH.
    If you don't have it:  winget install PostgreSQL.PostgreSQL.17

    Run:  powershell -ExecutionPolicy Bypass -File .\load-latestrouting.ps1
#>

# ==================== EDIT THESE ====================
$PGHOST     = "52.66.27.228"
$PGPORT     = "5432"
$PGDATABASE = "ehesdev"
$PGUSER     = "ehesqa_user"
# Supply this once per session: $env:EHES_SQL_PASSWORD = '<password>'
# If omitted, the script asks for it without displaying the value.
$PGPASSWORD = $env:EHES_SQL_PASSWORD
$PGSSLMODE  = "prefer"

$CSV        = "C:\Users\ayush\Downloads\all-meters.csv"
$BATCH      = 50000              # rows per commit

# NOTE: your sample meter_latestrouting row had projectid = 7, but every other
# table in this migration uses 1. Set this deliberately before running.
$PROJECTID  = 1

$GATEWAYID  = "direct_tcp"
$SINKID     = "direct_tcp"
$HOPCOUNT   = 12
$LINKSCORE  = 1
$SOURCEENDPOINT = 247
# ====================================================

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

$SKIPCSV     = Join-Path (Split-Path $CSV -Parent) "skipped-latestrouting.csv"
$csvForCopy  = ($CSV     -replace '\\', '/')
$skipForCopy = ($SKIPCSV -replace '\\', '/')

Write-Host "CSV     : $CSV  ($([math]::Round((Get-Item $CSV).Length/1MB,1)) MB)"
Write-Host "Skipped : $SKIPCSV"
Write-Host "Table   : public.meter_latestrouting"
Write-Host "Project : $PROJECTID"
Write-Host "DB      : $PGUSER@$PGHOST`:$PGPORT/$PGDATABASE`n"

$env:PGPASSWORD       = $PGPASSWORD
$env:PGSSLMODE        = $PGSSLMODE
$env:PGCLIENTENCODING = "UTF8"

# --- the whole job as one SQL script ---
$sql = @'
\set ON_ERROR_STOP on
\timing on

-- 1. staging table -----------------------------------------------------------
DROP TABLE IF EXISTS stg_rt;
DROP TABLE IF EXISTS stg_rt_skipped;

CREATE UNLOGGED TABLE stg_rt (
    idx      bigint PRIMARY KEY,
    nodeid   text,
    serial   text,
    nic      text,
    ipv6     text,
    port     text,
    template text,
    batch    text
);

-- 2. load the csv (nodeid comes straight from the csv) -------------------------
-- column order must match all-meters.csv: index,nodeid,serial,nic,ipv6,port,template,batch
\echo '>> copying csv ...'
\copy stg_rt (idx, nodeid, serial, nic, ipv6, port, template, batch) FROM '__CSVPATH__' WITH (FORMAT csv, HEADER true)

CREATE INDEX stg_rt_nodeid_idx ON stg_rt (nodeid);
CREATE INDEX stg_rt_serial_idx ON stg_rt (serial);
ANALYZE stg_rt;

-- 4. quarantine collisions ----------------------------------------------------
\echo '>> checking collisions ...'
CREATE UNLOGGED TABLE stg_rt_skipped (
    idx bigint, serial text, nodeid text, reason text
);

-- 4a. (projectid, meternumber) already present
--     DB-enforced: unique index "uq_projectid_meternumber" -- composite, so scoped to this project
INSERT INTO stg_rt_skipped (idx, serial, nodeid, reason)
SELECT s.idx, s.serial, s.nodeid, 'projectid+meternumber already exists in meter_latestrouting'
FROM stg_rt s
WHERE EXISTS (SELECT 1 FROM public.meter_latestrouting m
              WHERE m.projectid = __PROJECTID__ AND m.meternumber = s.serial);

-- 4b. nodeid already present in this project -- NOT DB-enforced, business rule only
--     (idx_meter_latestrouting_nodeid and idx_pro_node are both non-unique)
INSERT INTO stg_rt_skipped (idx, serial, nodeid, reason)
SELECT s.idx, s.serial, s.nodeid, 'nodeid already exists in meter_latestrouting for this project'
FROM stg_rt s
WHERE EXISTS (SELECT 1 FROM public.meter_latestrouting m
              WHERE m.projectid = __PROJECTID__ AND m.nodeid = s.nodeid)
  AND NOT EXISTS (SELECT 1 FROM stg_rt_skipped k WHERE k.idx = s.idx);

-- 4c. duplicates inside the csv itself (keeps the lowest idx)
INSERT INTO stg_rt_skipped (idx, serial, nodeid, reason)
SELECT s.idx, s.serial, s.nodeid, 'duplicate nodeid within the csv'
FROM stg_rt s
WHERE EXISTS (SELECT 1 FROM stg_rt t WHERE t.nodeid = s.nodeid AND t.idx < s.idx)
  AND NOT EXISTS (SELECT 1 FROM stg_rt_skipped k WHERE k.idx = s.idx);

CREATE INDEX stg_rt_skipped_idx ON stg_rt_skipped (idx);
DELETE FROM stg_rt s WHERE EXISTS (SELECT 1 FROM stg_rt_skipped k WHERE k.idx = s.idx);
ANALYZE stg_rt;

\echo '>> collision summary:'
SELECT reason, count(*) AS rows_skipped FROM stg_rt_skipped GROUP BY reason ORDER BY 2 DESC;
SELECT count(*) AS rows_to_insert FROM stg_rt;

-- 5. batched insert -----------------------------------------------------------
CREATE OR REPLACE PROCEDURE public.load_rt_batch(p_step bigint)
LANGUAGE plpgsql AS $proc$
DECLARE
    v_lo bigint; v_max bigint; v_n bigint; v_total bigint := 0;
    v_ts timestamptz := now();
BEGIN
    SELECT COALESCE(min(idx),0), COALESCE(max(idx),-1) INTO v_lo, v_max FROM stg_rt;

    WHILE v_lo <= v_max LOOP
        INSERT INTO public.meter_latestrouting (
            nodeid, gatewayid, createdat, hopcount, linkscore, sinkid,
            lastcommunicatedat, sourceendpoint, profilelastreceivedat,
            projectid, pingavailableat, meternumber
        )
        SELECT
            s.nodeid,            -- nodeid       101
            '__GATEWAYID__',     -- gatewayid
            v_ts,                -- createdat
            __HOPCOUNT__,        -- hopcount
            __LINKSCORE__,       -- linkscore
            '__SINKID__',        -- sinkid
            v_ts,                -- lastcommunicatedat
            __SOURCEENDPOINT__,  -- sourceendpoint
            v_ts,                -- profilelastreceivedat
            __PROJECTID__,       -- projectid
            v_ts,                -- pingavailableat
            s.serial             -- meternumber  MY000000101
        FROM stg_rt s
        WHERE s.idx >= v_lo AND s.idx < v_lo + p_step
        ON CONFLICT DO NOTHING;   -- safety net for concurrent writers

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
CALL public.load_rt_batch(__BATCH__);

-- 6. verify -------------------------------------------------------------------
SELECT count(*) AS total_rows_now FROM public.meter_latestrouting;

SELECT nodeid, meternumber, gatewayid, sinkid, hopcount, projectid, createdat
FROM public.meter_latestrouting
WHERE meternumber LIKE 'MY%'
ORDER BY meternumber DESC
LIMIT 5;

SELECT
  (SELECT count(*) FROM (SELECT projectid, meternumber FROM public.meter_latestrouting
      GROUP BY projectid, meternumber HAVING count(*) > 1) a) AS duplicate_project_meternumber,
  (SELECT count(*) FROM (SELECT nodeid FROM public.meter_latestrouting
      WHERE projectid = __PROJECTID__
      GROUP BY nodeid HAVING count(*) > 1) b)                 AS duplicate_nodeids_in_project;

-- 7. write skipped rows out, then clean up ------------------------------------
\echo '>> writing skipped rows ...'
\copy (SELECT idx, serial, nodeid, reason FROM stg_rt_skipped ORDER BY idx) TO '__SKIPPATH__' WITH (FORMAT csv, HEADER true)

DROP TABLE IF EXISTS stg_rt;
DROP TABLE IF EXISTS stg_rt_skipped;
DROP PROCEDURE IF EXISTS public.load_rt_batch(bigint);
'@

$sql = $sql.Replace('__CSVPATH__',        $csvForCopy).
            Replace('__SKIPPATH__',       $skipForCopy).
            Replace('__BATCH__',          "$BATCH").
            Replace('__PROJECTID__',      "$PROJECTID").
            Replace('__GATEWAYID__',      $GATEWAYID).
            Replace('__SINKID__',         $SINKID).
            Replace('__HOPCOUNT__',       "$HOPCOUNT").
            Replace('__LINKSCORE__',      "$LINKSCORE").
            Replace('__SOURCEENDPOINT__', "$SOURCEENDPOINT")

$tmp = Join-Path $env:TEMP "load-latestrouting-$(Get-Date -f yyyyMMdd-HHmmss).sql"
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
