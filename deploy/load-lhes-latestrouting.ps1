<#
Bulk loads all-meters.csv into LHES dbo.LatestRouting.

LHES routing is keyed only by NodeId; it does not contain ProjectId or
MeterNo. Existing/duplicate node ids are written to skipped-lhes-latestrouting.csv.
Run this after load-lhes-meters.ps1.
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
$GatewayId = 'direct_tcp'; $SinkId = 'direct_tcp'; $HopCount = 12; $LinkScore = 1; $SourceEndpoint = 247
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
$skipCsv = Join-Path (Split-Path -Parent $CSV) 'skipped-lhes-latestrouting.csv'; $now=[DateTime]::UtcNow
$connection=[System.Data.SqlClient.SqlConnection]::new($ConnectionString);$connection.Open()
try {
    $command=$connection.CreateCommand();$command.CommandTimeout=0
    $command.CommandText=@'
SET XACT_ABORT ON;
IF OBJECT_ID('dbo.LatestRouting', 'U') IS NULL THROW 50000, 'Missing dbo.LatestRouting.', 1;
CREATE TABLE #source (idx bigint NOT NULL PRIMARY KEY,nodeid nvarchar(100) NOT NULL);
CREATE TABLE #skipped (idx bigint NOT NULL,nodeid nvarchar(100),reason nvarchar(200) NOT NULL);
'@;[void]$command.ExecuteNonQuery()
    $data=[System.Data.DataTable]::new();[void]$data.Columns.Add('idx',[Int64]);[void]$data.Columns.Add('nodeid',[String]);$count=0L
    Import-Csv -LiteralPath $CSV | ForEach-Object { $count++;$row=$data.NewRow();$row.idx=[Int64]$_.index;$row.nodeid=$_.nodeid;$data.Rows.Add($row);if($data.Rows.Count -ge $BatchSize){$bulk=[System.Data.SqlClient.SqlBulkCopy]::new($connection);$bulk.DestinationTableName='#source';$bulk.BatchSize=$BatchSize;$bulk.BulkCopyTimeout=0;[void]$bulk.ColumnMappings.Add('idx','idx');[void]$bulk.ColumnMappings.Add('nodeid','nodeid');$bulk.WriteToServer($data);$bulk.Close();$data.Clear()} }
    if($data.Rows.Count){$bulk=[System.Data.SqlClient.SqlBulkCopy]::new($connection);$bulk.DestinationTableName='#source';$bulk.BatchSize=$BatchSize;$bulk.BulkCopyTimeout=0;[void]$bulk.ColumnMappings.Add('idx','idx');[void]$bulk.ColumnMappings.Add('nodeid','nodeid');$bulk.WriteToServer($data);$bulk.Close()}
    $command.CommandText=@'
INSERT #skipped SELECT s.idx,s.nodeid,'NodeId already exists in dbo.LatestRouting' FROM #source s WHERE EXISTS (SELECT 1 FROM dbo.LatestRouting t WHERE t.NodeId=s.nodeid);
INSERT #skipped SELECT s.idx,s.nodeid,'duplicate NodeId within the CSV' FROM #source s WHERE EXISTS (SELECT 1 FROM #source x WHERE x.nodeid=s.nodeid AND x.idx<s.idx) AND NOT EXISTS (SELECT 1 FROM #skipped k WHERE k.idx=s.idx);
DELETE s FROM #source s WHERE EXISTS (SELECT 1 FROM #skipped k WHERE k.idx=s.idx);
'@;[void]$command.ExecuteNonQuery()
    $command.CommandText=@'
INSERT dbo.LatestRouting (CreatedDate,NodeId,GatewayId,SinkId,LinkScore,LastCommunicatedOn,SourceEndpoint,HopCount,GatewayId2,SinkId2,GatewayId3,SinkId3,IsCommunicating)
SELECT @Now,nodeid,@GatewayId,@SinkId,@LinkScore,@Now,@SourceEndpoint,@HopCount,NULL,NULL,NULL,NULL,1 FROM #source;
SELECT idx,nodeid,reason FROM #skipped ORDER BY idx;
'@
    $command.Parameters.Clear();foreach($p in @(@('Now',$now),@('GatewayId',$GatewayId),@('SinkId',$SinkId),@('LinkScore',$LinkScore),@('SourceEndpoint',$SourceEndpoint),@('HopCount',$HopCount))){[void]$command.Parameters.AddWithValue('@'+$p[0],$p[1])}
    $reader=$command.ExecuteReader();$skipped=[System.Data.DataTable]::new();$skipped.Load($reader);$reader.Close();$skipped|Export-Csv -LiteralPath $skipCsv -NoTypeInformation
    Write-Host "OK - inserted $($count-$skipped.Rows.Count) of $count rows. Skipped: $($skipped.Rows.Count) ($skipCsv)" -ForegroundColor Green
} finally {$connection.Dispose()}
