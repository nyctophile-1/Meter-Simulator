<#
Bulk loads all-meters.csv into LHES dbo.NamePlate.

Rows whose NodeId or MeterNo already exists, plus duplicate NodeIds/MeterNos
inside the CSV, are written to skipped-lhes-meters.csv.  Set the connection
and registration defaults below, then run this before the other two scripts.
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
$TemplateId = 111
$MeterCategory = 'D1'
$MeterType = '6'
$Manufacturer = 'Kushal (Kimbal)'
$FirmwareVersion = 'AGXX01'
$Rating = '(10-60)A'
$CTRatio = 1; $PTRatio = 1; $YearOfManufacture = 2025; $BlockCapturePeriod = 30
# ====================================================

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $CSV)) { throw "CSV not found: $CSV" }
if ($MeterCategory -notin 'D1','D2','D3') { throw 'MeterCategory must be D1, D2, or D3.' }
if ($MeterType -notin '6','7','8','10') { throw 'MeterType must be 6, 7, 8, or 10.' }
if ([string]::IsNullOrWhiteSpace($SqlPassword)) {
    $securePassword = Read-Host "Password for $SqlUser@$SqlServer" -AsSecureString
    $SqlPassword = [System.Net.NetworkCredential]::new('', $securePassword).Password
}
$builder = [System.Data.SqlClient.SqlConnectionStringBuilder]::new()
$builder['Data Source'] = $SqlServer; $builder['Initial Catalog'] = $SqlDatabase
$builder['User ID'] = $SqlUser; $builder['Password'] = $SqlPassword
$builder['TrustServerCertificate'] = $true; $builder['Connect Timeout'] = 30
$ConnectionString = $builder.ConnectionString

$skipCsv = Join-Path (Split-Path -Parent $CSV) 'skipped-lhes-meters.csv'
$now = [DateTime]::UtcNow
$connection = [System.Data.SqlClient.SqlConnection]::new($ConnectionString); $connection.Open()
try {
    $command = $connection.CreateCommand(); $command.CommandTimeout = 0
    $command.CommandText = @'
SET XACT_ABORT ON;
IF OBJECT_ID('dbo.NamePlate', 'U') IS NULL THROW 50000, 'Missing dbo.NamePlate.', 1;
CREATE TABLE #source (idx bigint NOT NULL PRIMARY KEY,nodeid nvarchar(100) NOT NULL,meterno nvarchar(100) NOT NULL,ip nvarchar(100),port int NULL);
CREATE TABLE #skipped (idx bigint NOT NULL,nodeid nvarchar(100),meterno nvarchar(100),ip nvarchar(100),reason nvarchar(200) NOT NULL);
'@
    [void]$command.ExecuteNonQuery()
    $data = [System.Data.DataTable]::new(); [void]$data.Columns.Add('idx',[Int64]); [void]$data.Columns.Add('nodeid',[String]); [void]$data.Columns.Add('meterno',[String]); [void]$data.Columns.Add('ip',[String]); [void]$data.Columns.Add('port',[Int32])
    $count = 0L
    Import-Csv -LiteralPath $CSV | ForEach-Object {
        $count++; $row=$data.NewRow(); $row.idx=[Int64]$_.index; $row.nodeid=$_.nodeid; $row.meterno=$_.serial; $row.ip=$_.ipv6; $row.port=[int]$_.port; $data.Rows.Add($row)
        if($data.Rows.Count -ge $BatchSize){ $bulk=[System.Data.SqlClient.SqlBulkCopy]::new($connection); $bulk.DestinationTableName='#source'; $bulk.BatchSize=$BatchSize; $bulk.BulkCopyTimeout=0; foreach($c in 'idx','nodeid','meterno','ip','port'){[void]$bulk.ColumnMappings.Add($c,$c)}; $bulk.WriteToServer($data);$bulk.Close();$data.Clear() }
    }
    if($data.Rows.Count){ $bulk=[System.Data.SqlClient.SqlBulkCopy]::new($connection);$bulk.DestinationTableName='#source';$bulk.BatchSize=$BatchSize;$bulk.BulkCopyTimeout=0;foreach($c in 'idx','nodeid','meterno','ip','port'){[void]$bulk.ColumnMappings.Add($c,$c)};$bulk.WriteToServer($data);$bulk.Close() }
    $command.CommandText = @'
INSERT #skipped SELECT s.idx,s.nodeid,s.meterno,s.ip,'NodeId already exists in dbo.NamePlate' FROM #source s WHERE EXISTS (SELECT 1 FROM dbo.NamePlate t WHERE t.NodeId=s.nodeid);
INSERT #skipped SELECT s.idx,s.nodeid,s.meterno,s.ip,'MeterNo already exists in dbo.NamePlate' FROM #source s WHERE EXISTS (SELECT 1 FROM dbo.NamePlate t WHERE t.MeterNo=s.meterno) AND NOT EXISTS (SELECT 1 FROM #skipped k WHERE k.idx=s.idx);
INSERT #skipped SELECT s.idx,s.nodeid,s.meterno,s.ip,'duplicate NodeId within the CSV' FROM #source s WHERE EXISTS (SELECT 1 FROM #source x WHERE x.nodeid=s.nodeid AND x.idx<s.idx) AND NOT EXISTS (SELECT 1 FROM #skipped k WHERE k.idx=s.idx);
INSERT #skipped SELECT s.idx,s.nodeid,s.meterno,s.ip,'duplicate MeterNo within the CSV' FROM #source s WHERE EXISTS (SELECT 1 FROM #source x WHERE x.meterno=s.meterno AND x.idx<s.idx) AND NOT EXISTS (SELECT 1 FROM #skipped k WHERE k.idx=s.idx);
DELETE s FROM #source s WHERE EXISTS (SELECT 1 FROM #skipped k WHERE k.idx=s.idx);
'@; [void]$command.ExecuteNonQuery()
    $command.CommandText = @'
INSERT dbo.NamePlate (Guid,MeterNo,DeviceId,Manufacturer,FirmwareVersion,MeterType,MeterCategory,Rating,YearOfManufacture,CTRatio,PTRatio,CreatedDate,NodeId,MeterTemplateId,InstalledOn,OriginalInstalledOn,IP,Port,CommunicationModule,MigrationDateTime,BlockCapturePeriod)
SELECT NEWID(),meterno,'MAYA00'+REPLACE(REPLACE(REPLACE(meterno,'M',''),'Y',''),' ',''),@Manufacturer,@FirmwareVersion,@MeterType,@MeterCategory,@Rating,@YearOfManufacture,@CTRatio,@PTRatio,@Now,nodeid,@TemplateId,@Now,@Now,ip,port,'TCP',@Now,@BlockCapturePeriod FROM #source;
SELECT idx,nodeid,meterno,ip,reason FROM #skipped ORDER BY idx;
'@
    $command.Parameters.Clear(); foreach($p in @(@('Manufacturer',$Manufacturer),@('FirmwareVersion',$FirmwareVersion),@('MeterType',$MeterType),@('MeterCategory',$MeterCategory),@('Rating',$Rating),@('YearOfManufacture',$YearOfManufacture),@('CTRatio',$CTRatio),@('PTRatio',$PTRatio),@('Now',$now),@('TemplateId',$TemplateId),@('BlockCapturePeriod',$BlockCapturePeriod))){[void]$command.Parameters.AddWithValue('@'+$p[0],$p[1])}
    $reader=$command.ExecuteReader();$skipped=[System.Data.DataTable]::new();$skipped.Load($reader);$reader.Close();$skipped|Export-Csv -LiteralPath $skipCsv -NoTypeInformation
    Write-Host "OK - inserted $($count-$skipped.Rows.Count) of $count rows. Skipped: $($skipped.Rows.Count) ($skipCsv)" -ForegroundColor Green
} finally { $connection.Dispose() }
