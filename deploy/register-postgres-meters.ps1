<#
Reusable registration for PostgreSQL's LHES-compatible nameplate/metersecurity/latestrouting schema.
Dry-run by default. Password comes from PG_REGISTRATION_PASSWORD. Requires PowerShell 7 on .NET 10
and Npgsql 10 (pass DLL paths or use an existing NuGet cache). See postgres-registration.md.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$Server,
 [int]$Port=5432,
 [Parameter(Mandatory)][string]$Database,
 [Parameter(Mandatory)][string]$Username,
 [Parameter(Mandatory)][string]$CsvPath,
 [string]$Schema='kimbaldb_dbo',
 [int]$TemplateId=93,
 [ValidateSet('D1','D2','D3')][string]$Category='D1',
 [ValidateSet('6','7','8','10')][string]$MeterType='6',
 [ValidateSet(15,30)][int]$CapturePeriod=15,
 [string]$GatewayId='direct_4g',
 [string]$SinkId='direct_4g',
 [int]$SourceEndpoint=13,
 [ValidateSet('Require','VerifyFull','Disable')][string]$SslMode='Require',
 [string]$ReportDirectory=(Join-Path (Get-Location) 'registration-report'),
 [string]$NpgsqlAssembly,
 [string]$LoggingAssembly,
 [switch]$PreserveExistingRoutes,
 [switch]$Apply
)
$ErrorActionPreference='Stop'
if($Schema -notmatch '^[a-z_][a-z0-9_]*$'){throw 'Invalid schema identifier'}
if([string]::IsNullOrWhiteSpace($env:PG_REGISTRATION_PASSWORD)){throw 'Set PG_REGISTRATION_PASSWORD before running.'}
if(-not $NpgsqlAssembly){$NpgsqlAssembly=Join-Path $env:USERPROFILE '.nuget/packages/npgsql/10.0.3/lib/net10.0/Npgsql.dll'}
if(-not $LoggingAssembly){$LoggingAssembly=Join-Path $env:USERPROFILE '.nuget/packages/microsoft.extensions.logging.abstractions/10.0.0/lib/net10.0/Microsoft.Extensions.Logging.Abstractions.dll'}
Add-Type -Path $LoggingAssembly
Add-Type -Path $NpgsqlAssembly
$rows=@(Import-Csv -LiteralPath $CsvPath)
if(-not $rows.Count){throw 'CSV is empty'}
$nodes=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$serials=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($row in $rows){
 if($row.nodeid -notmatch '^\d{1,10}$' -or $row.serial -notmatch '^[A-Za-z0-9_-]{1,50}$' -or $row.nic -ne 'MqttWirepas'){throw 'Expected valid nodeid, serial and MqttWirepas CSV rows.'}
 if(-not $nodes.Add($row.nodeid) -or -not $serials.Add($row.serial)){throw 'Duplicate nodeid or serial in CSV'}
}
New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
$builder=[Npgsql.NpgsqlConnectionStringBuilder]::new()
$builder['Host']=$Server;$builder['Port']=$Port;$builder['Database']=$Database;$builder['Username']=$Username
$builder['Password']=$env:PG_REGISTRATION_PASSWORD;$builder['SSL Mode']=$SslMode;$builder['Timeout']=15
$connection=[Npgsql.NpgsqlConnection]::new($builder.ConnectionString)
$transaction=$null
function Query([string]$sql){
 $command=$connection.CreateCommand();$command.CommandTimeout=180;$command.Transaction=$transaction
 $command.CommandText=$sql.Replace('__SCHEMA__','"'+$Schema+'"')
 foreach($pair in @(@('template',$TemplateId),@('category',$Category),@('metertype',$MeterType),@('period',$CapturePeriod),@('gateway',$GatewayId),@('sink',$SinkId),@('endpoint',$SourceEndpoint),@('preserve',[bool]$PreserveExistingRoutes))){[void]$command.Parameters.AddWithValue($pair[0],$pair[1])}
 try {$adapter=[Npgsql.NpgsqlDataAdapter]::new($command);$dataset=[Data.DataSet]::new();[void]$adapter.Fill($dataset);return ,$dataset} finally {$command.Dispose()}
}
try {
 $connection.Open()
 [void](Query 'CREATE TEMP TABLE registration_source(nodeid text PRIMARY KEY,serial text UNIQUE);')
 $csv=$rows | Select-Object nodeid,serial | ConvertTo-Csv -NoTypeInformation
 $writer=$connection.BeginTextImport('COPY registration_source FROM STDIN (FORMAT CSV,HEADER TRUE)')
 try {$writer.Write(($csv -join "`n")+"`n")} finally {$writer.Dispose()}
 [void](Query 'ANALYZE registration_source;')
 $template=Query 'SELECT id FROM __SCHEMA__.metertemplate WHERE id=@template;'
 if($template.Tables[0].Rows.Count -ne 1){throw 'Template is missing or ambiguous.'}
 $transaction=$connection.BeginTransaction()
 # Registration tables are locked only for apply, preventing check/insert races. Readers remain allowed.
 if($Apply){[void](Query "SET LOCAL lock_timeout='15s'; LOCK TABLE __SCHEMA__.nameplate,__SCHEMA__.metersecurity,__SCHEMA__.latestrouting IN SHARE ROW EXCLUSIVE MODE;")}
 $plan=Query (Get-Content (Join-Path $PSScriptRoot 'register-postgres-plan.sql') -Raw)
 $conflicts=$plan.Tables[0]
 $conflicts | Export-Csv (Join-Path $ReportDirectory 'conflicts.csv') -NoTypeInformation
 $eligible=[int]$plan.Tables[1].Rows[0]['eligible']
 $before=$plan.Tables[1].Rows[0]
 if($Apply){
  [void](Query (Get-Content (Join-Path $PSScriptRoot 'register-postgres-apply.sql') -Raw))
  $verified=Query 'SELECT count(*) AS complete FROM registration_eligible s JOIN __SCHEMA__.nameplate n ON n.nodeid::text=s.nodeid AND n.meterno::text=s.serial JOIN __SCHEMA__.metersecurity k ON k.meterno::text=s.serial JOIN __SCHEMA__.latestrouting r ON r.nodeid::text=s.nodeid WHERE n.metercategory::text=@category AND n.metertemplateid=@template AND n.blockcaptureperiod=@period AND (@preserve OR (r.gatewayid::text=@gateway AND r.sinkid::text=@sink));'
  if([int]$verified.Tables[0].Rows[0]['complete'] -ne $eligible){throw 'Verification failed; transaction will roll back.'}
  $transaction.Commit()
 } else {$transaction.Rollback()}
 $transaction.Dispose();$transaction=$null
 $summary=[pscustomobject]@{Server=$Server;Database=$Database;Schema=$Schema;Applied=[bool]$Apply;Input=$rows.Count;Eligible=$eligible;Conflicts=$conflicts.Rows.Count;NewNameplates=[int]$before['new_nameplates'];NewSecurity=[int]$before['new_security'];NewRouting=[int]$before['new_routing'];TemplateId=$TemplateId;Category=$Category;CapturePeriod=$CapturePeriod;SslMode=$SslMode;PreservedExistingRoutes=[bool]$PreserveExistingRoutes;CsvSha256=(Get-FileHash -LiteralPath $CsvPath).Hash;Utc=[DateTime]::UtcNow}
 $summary | ConvertTo-Json | Tee-Object -FilePath (Join-Path $ReportDirectory 'summary.json')
} finally {if($transaction){$transaction.Rollback();$transaction.Dispose()};$connection.Dispose()}

