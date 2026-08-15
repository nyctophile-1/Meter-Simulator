<#
Bulk loads all-meters.csv into LHES dbo.MeterSecurity.

Uses MeterNo as the LHES key.  It does not add a node id because the LHES
MeterSecurity schema has no NodeId column.  Existing meter numbers and
duplicates within the CSV are reported in skipped-lhes-security.csv.

Run (after setting the connection string):
  powershell -ExecutionPolicy Bypass -File .\load-lhes-security.ps1
#>

# ==================== EDIT THESE ====================
$SqlServer = '43.204.185.146'
$SqlDatabase = 'SizeChangeEQA'
$SqlUser = 'KimbalUser'
# Supply this once per session: $env:LHES_SQL_PASSWORD = '<password>'
# If omitted, the script asks for it without displaying the value.
$SqlPassword = $env:LHES_SQL_PASSWORD
$CSV = "C:\Users\ayush\Downloads\all-meters.csv"
$BatchSize = 50000
$GlobalKey = "AAAAAAAAAAAAAAAA"
$HLSFWSecret = "AAAAAAAAAAAAAAAA"
$HLSUSSecret = "AAAAAAAAAAAAAAAA"
$LLSMRSecret = "12345678"
$MasterKey = "AAAAAAAAAAAAAAAA"
# ====================================================

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $CSV)) { throw "CSV not found: $CSV" }
if ([string]::IsNullOrWhiteSpace($SqlPassword)) {
    $securePassword = Read-Host "Password for $SqlUser@$SqlServer" -AsSecureString
    $SqlPassword = [System.Net.NetworkCredential]::new('', $securePassword).Password
}
$builder = [System.Data.SqlClient.SqlConnectionStringBuilder]::new()
$builder['Data Source'] = $SqlServer; $builder['Initial Catalog'] = $SqlDatabase
$builder['User ID'] = $SqlUser; $builder['Password'] = $SqlPassword
$builder['TrustServerCertificate'] = $true; $builder['Connect Timeout'] = 30
$ConnectionString = $builder.ConnectionString

$skipCsv = Join-Path (Split-Path -Parent $CSV) 'skipped-lhes-security.csv'
$now = [DateTime]::UtcNow

$connection = [System.Data.SqlClient.SqlConnection]::new($ConnectionString)
$connection.Open()
try {
    $command = $connection.CreateCommand()
    $command.CommandTimeout = 0
    $command.CommandText = @'
SET XACT_ABORT ON;
IF OBJECT_ID('dbo.MeterSecurity', 'U') IS NULL THROW 50000, 'Missing dbo.MeterSecurity.', 1;
CREATE TABLE #source (idx bigint NOT NULL PRIMARY KEY, nodeid nvarchar(100), meterno nvarchar(100) NOT NULL);
CREATE TABLE #skipped (idx bigint NOT NULL, nodeid nvarchar(100), meterno nvarchar(100), reason nvarchar(200) NOT NULL);
'@
    [void]$command.ExecuteNonQuery()

    $data = [System.Data.DataTable]::new()
    [void]$data.Columns.Add('idx', [Int64])
    [void]$data.Columns.Add('nodeid', [String])
    [void]$data.Columns.Add('meterno', [String])
    $rowNumber = 0L
    Import-Csv -LiteralPath $CSV | ForEach-Object {
        $rowNumber++
        $row = $data.NewRow(); $row.idx = [Int64]$_.index; $row.nodeid = $_.nodeid; $row.meterno = $_.serial
        $data.Rows.Add($row)
        if ($data.Rows.Count -ge $BatchSize) {
            $bulk = [System.Data.SqlClient.SqlBulkCopy]::new($connection)
            $bulk.DestinationTableName = '#source'; $bulk.BatchSize = $BatchSize; $bulk.BulkCopyTimeout = 0
            [void]$bulk.ColumnMappings.Add('idx', 'idx'); [void]$bulk.ColumnMappings.Add('nodeid', 'nodeid'); [void]$bulk.ColumnMappings.Add('meterno', 'meterno')
            $bulk.WriteToServer($data); $bulk.Close(); $data.Clear()
        }
    }
    if ($data.Rows.Count) {
        $bulk = [System.Data.SqlClient.SqlBulkCopy]::new($connection); $bulk.DestinationTableName = '#source'; $bulk.BatchSize = $BatchSize; $bulk.BulkCopyTimeout = 0
        [void]$bulk.ColumnMappings.Add('idx', 'idx'); [void]$bulk.ColumnMappings.Add('nodeid', 'nodeid'); [void]$bulk.ColumnMappings.Add('meterno', 'meterno')
        $bulk.WriteToServer($data); $bulk.Close()
    }

    $command.CommandText = @'
INSERT #skipped (idx,nodeid,meterno,reason)
SELECT s.idx,s.nodeid,s.meterno,'MeterNo already exists in dbo.MeterSecurity'
FROM #source s WHERE EXISTS (SELECT 1 FROM dbo.MeterSecurity t WHERE t.MeterNo=s.meterno);
INSERT #skipped (idx,nodeid,meterno,reason)
SELECT s.idx,s.nodeid,s.meterno,'duplicate MeterNo within the CSV'
FROM #source s WHERE EXISTS (SELECT 1 FROM #source x WHERE x.meterno=s.meterno AND x.idx<s.idx)
  AND NOT EXISTS (SELECT 1 FROM #skipped k WHERE k.idx=s.idx);
DELETE s FROM #source s WHERE EXISTS (SELECT 1 FROM #skipped k WHERE k.idx=s.idx);
'@
    [void]$command.ExecuteNonQuery()

    $command.CommandText = @'
INSERT dbo.MeterSecurity (MeterNo,MasterKey,GlobalKey,HLSUSSecret,HLSFWSecret,LLSMRSecret,CreatedDate,UpdatedDate)
SELECT meterno,@MasterKey,@GlobalKey,@HLSUSSecret,@HLSFWSecret,@LLSMRSecret,@Now,@Now FROM #source;
SELECT idx,nodeid,meterno,reason FROM #skipped ORDER BY idx;
'@
    $command.Parameters.Clear()
    foreach ($p in @(@('MasterKey',$MasterKey),@('GlobalKey',$GlobalKey),@('HLSUSSecret',$HLSUSSecret),@('HLSFWSecret',$HLSFWSecret),@('LLSMRSecret',$LLSMRSecret),@('Now',$now))) { [void]$command.Parameters.AddWithValue('@' + $p[0], $p[1]) }
    $reader = $command.ExecuteReader(); $skipped = [System.Data.DataTable]::new(); $skipped.Load($reader); $reader.Close()
    $skipped | Export-Csv -LiteralPath $skipCsv -NoTypeInformation
    Write-Host "OK - inserted $($rowNumber - $skipped.Rows.Count) of $rowNumber rows. Skipped: $($skipped.Rows.Count) ($skipCsv)" -ForegroundColor Green
}
finally { $connection.Dispose() }
