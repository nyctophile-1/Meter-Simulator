<#
    load-security.ps1
    Bulk-loads batch-10-lakh.csv into public.meter_security.

    Uniqueness enforced on meternumber (and nodeid, defensively). Rows that
    would collide are skipped individually and written to
    skipped-security.csv next to the input file.

    Requires psql (PostgreSQL client) on PATH.
    If you don't have it:  winget install PostgreSQL.PostgreSQL.17

    Run:  powershell -ExecutionPolicy Bypass -File .\load-security.ps1
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
$PROJECTID  = 1

# security key material - same for every row, from your sample
$GLOBALKEY   = "AAAAAAAAAAAAAAAA"
$HLSFWSECRET = "AAAAAAAAAAAAAAAA"
$HLSUSSECRET = "AAAAAAAAAAAAAAAA"
$LLSMRSECRET = "12345678"
$MASTERKEY   = "AAAAAAAAAAAAAAAA"
$GLOBALAUTH  = "AAAAAAAAAAAAAAAA"
$UNICASTENC  = "AAAAAAAAAAAAAAAA"
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

$SKIPCSV     = Join-Path (Split-Path $CSV -Parent) "skipped-security.csv"
$csvForCopy  = ($CSV     -replace '\\', '/')
$skipForCopy = ($SKIPCSV -replace '\\', '/')

Write-Host "CSV     : $CSV  ($([math]::Round((Get-Item $CSV).Length/1MB,1)) MB)"
Write-Host "Skipped : $SKIPCSV"
Write-Host "Table   : public.meter_security"
Write-Host "DB      : $PGUSER@$PGHOST`:$PGPORT/$PGDATABASE`n"

$env:PGPASSWORD       = $PGPASSWORD
$env:PGSSLMODE        = $PGSSLMODE
$env:PGCLIENTENCODING = "UTF8"

# --- the whole job as one SQL script ---
$sql = @'
\set ON_ERROR_STOP on
\timing on

-- 1. staging table -----------------------------------------------------------
DROP TABLE IF EXISTS stg_sec;
DROP TABLE IF EXISTS stg_sec_skipped;

CREATE UNLOGGED TABLE stg_sec (
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
\copy stg_sec (idx, nodeid, serial, nic, ipv6, port, template, batch) FROM '__CSVPATH__' WITH (FORMAT csv, HEADER true)

CREATE INDEX stg_sec_nodeid_idx ON stg_sec (nodeid);
CREATE INDEX stg_sec_serial_idx ON stg_sec (serial);
ANALYZE stg_sec;

-- 4. quarantine collisions ----------------------------------------------------
\echo '>> checking collisions ...'
CREATE UNLOGGED TABLE stg_sec_skipped (
    idx bigint, serial text, nodeid text, reason text
);

-- 4a. nodeid already present  -- DB-enforced: unique index "unique_nodeid" (global, not per project)
INSERT INTO stg_sec_skipped (idx, serial, nodeid, reason)
SELECT s.idx, s.serial, s.nodeid, 'nodeid already exists in meter_security'
FROM stg_sec s
WHERE EXISTS (SELECT 1 FROM public.meter_security m WHERE m.nodeid = s.nodeid);

-- 4b. meternumber already present -- NOT DB-enforced, business rule only
INSERT INTO stg_sec_skipped (idx, serial, nodeid, reason)
SELECT s.idx, s.serial, s.nodeid, 'meternumber already exists in meter_security'
FROM stg_sec s
WHERE EXISTS (SELECT 1 FROM public.meter_security m WHERE m.meternumber = s.serial)
  AND NOT EXISTS (SELECT 1 FROM stg_sec_skipped k WHERE k.idx = s.idx);

-- 4c. duplicates inside the csv itself (keeps the lowest idx)
INSERT INTO stg_sec_skipped (idx, serial, nodeid, reason)
SELECT s.idx, s.serial, s.nodeid, 'duplicate nodeid within the csv'
FROM stg_sec s
WHERE EXISTS (SELECT 1 FROM stg_sec t WHERE t.nodeid = s.nodeid AND t.idx < s.idx)
  AND NOT EXISTS (SELECT 1 FROM stg_sec_skipped k WHERE k.idx = s.idx);

CREATE INDEX stg_sec_skipped_idx ON stg_sec_skipped (idx);
DELETE FROM stg_sec s WHERE EXISTS (SELECT 1 FROM stg_sec_skipped k WHERE k.idx = s.idx);
ANALYZE stg_sec;

\echo '>> collision summary:'
SELECT reason, count(*) AS rows_skipped FROM stg_sec_skipped GROUP BY reason ORDER BY 2 DESC;
SELECT count(*) AS rows_to_insert FROM stg_sec;

-- 5. batched insert -----------------------------------------------------------
CREATE OR REPLACE PROCEDURE public.load_sec_batch(p_step bigint)
LANGUAGE plpgsql AS $proc$
DECLARE
    v_lo bigint; v_max bigint; v_n bigint; v_total bigint := 0;
BEGIN
    SELECT COALESCE(min(idx),0), COALESCE(max(idx),-1) INTO v_lo, v_max FROM stg_sec;

    WHILE v_lo <= v_max LOOP
        INSERT INTO public.meter_security (
            nodeid, projectid, globalkey, hlsfwsecret, hlsussecret, llsmrsecret,
            masterkey, meternumber, "GlobalAuthenticationKey", "UnicastEncryptionKey"
        )
        SELECT
            s.nodeid,           -- nodeid       101
            __PROJECTID__,      -- projectid
            '__GLOBALKEY__',    -- globalkey
            '__HLSFWSECRET__',  -- hlsfwsecret
            '__HLSUSSECRET__',  -- hlsussecret
            '__LLSMRSECRET__',  -- llsmrsecret
            '__MASTERKEY__',    -- masterkey
            s.serial,           -- meternumber  MY000000101
            '__GLOBALAUTH__',   -- GlobalAuthenticationKey
            '__UNICASTENC__'    -- UnicastEncryptionKey
        FROM stg_sec s
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
CALL public.load_sec_batch(__BATCH__);

-- 6. verify -------------------------------------------------------------------
SELECT count(*) AS total_rows_now FROM public.meter_security;

SELECT nodeid, meternumber, projectid, globalkey, llsmrsecret
FROM public.meter_security
WHERE meternumber LIKE 'MY%'
ORDER BY meternumber DESC
LIMIT 5;

SELECT
  (SELECT count(*) FROM (SELECT nodeid FROM public.meter_security
      GROUP BY nodeid HAVING count(*) > 1) a)      AS duplicate_nodeids_remaining,
  (SELECT count(*) FROM (SELECT meternumber FROM public.meter_security
      GROUP BY meternumber HAVING count(*) > 1) b) AS duplicate_meternumbers_remaining;

-- 7. write skipped rows out, then clean up ------------------------------------
\echo '>> writing skipped rows ...'
\copy (SELECT idx, serial, nodeid, reason FROM stg_sec_skipped ORDER BY idx) TO '__SKIPPATH__' WITH (FORMAT csv, HEADER true)

DROP TABLE IF EXISTS stg_sec;
DROP TABLE IF EXISTS stg_sec_skipped;
DROP PROCEDURE IF EXISTS public.load_sec_batch(bigint);
'@

$sql = $sql.Replace('__CSVPATH__',     $csvForCopy).
            Replace('__SKIPPATH__',    $skipForCopy).
            Replace('__BATCH__',       "$BATCH").
            Replace('__PROJECTID__',   "$PROJECTID").
            Replace('__GLOBALKEY__',   $GLOBALKEY).
            Replace('__HLSFWSECRET__', $HLSFWSECRET).
            Replace('__HLSUSSECRET__', $HLSUSSECRET).
            Replace('__LLSMRSECRET__', $LLSMRSECRET).
            Replace('__MASTERKEY__',   $MASTERKEY).
            Replace('__GLOBALAUTH__',  $GLOBALAUTH).
            Replace('__UNICASTENC__',  $UNICASTENC)

$tmp = Join-Path $env:TEMP "load-security-$(Get-Date -f yyyyMMdd-HHmmss).sql"
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
