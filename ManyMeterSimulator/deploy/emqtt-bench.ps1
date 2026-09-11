# Run with PowerShell 7 and an installed official emqtt_bench binary.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BrokerHost,
    [ValidateSet('pub', 'sub')][string]$Mode = 'pub',
    [ValidateRange(1, 65535)][int]$Port = 1883,
    [ValidateRange(1, 60000)][int]$Clients = 8,
    [ValidateSet(0, 1, 2)][int]$Qos = 2,
    [ValidateRange(1, 65535)][int]$Inflight = 1,
    [ValidateRange(1, 10485760)][int]$PayloadBytes = 256,
    [ValidateRange(0, 3600000)][int]$IntervalMs = 0,
    [ValidateRange(1, 86400)][int]$DurationSeconds = 60,
    [ValidateSet(4, 5)][int]$MqttVersion = 5,
    [string]$TopicPrefix = 'maya-bench',
    [string]$Username = $env:EMQTT_BENCH_USERNAME,
    [switch]$Tls,
    [string]$CaCertFile,
    [string]$Binary = 'emqtt_bench',
    [switch]$Run
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($BrokerHost) -or $BrokerHost.StartsWith('-')) { throw 'Specify a broker hostname.' }
if ([string]::IsNullOrWhiteSpace($TopicPrefix) -or $TopicPrefix.IndexOfAny([char[]]'#+%') -ge 0) {
    throw 'TopicPrefix must be a literal prefix without MQTT wildcards or benchmark substitutions.'
}
if ($CaCertFile -and -not $Tls) { throw 'CaCertFile requires -Tls.' }
$benchArgs = [Collections.Generic.List[string]]::new()
foreach ($value in @($Mode, '-h', $BrokerHost, '-p', "$Port", '-V', "$MqttVersion", '-c', "$Clients",
    '-q', "$Qos", '--prefix', "maya-$Mode-$([guid]::NewGuid().ToString('N'))", '--log_to', 'console')) {
    $benchArgs.Add($value)
}
if ($Mode -eq 'pub') {
    foreach ($value in @('-t', "$TopicPrefix/%i", '-s', "$PayloadBytes", '-I', "$IntervalMs", '-F', "$Inflight", '-w', 'true')) {
        $benchArgs.Add($value)
    }
} else { $benchArgs.Add('-t'); $benchArgs.Add("$TopicPrefix/#") }
if ($Tls) { $benchArgs.Add('--ssl') }
if ($CaCertFile) { $benchArgs.Add('--cacertfile'); $benchArgs.Add((Resolve-Path -LiteralPath $CaCertFile).Path) }
if ($Username) { $benchArgs.Add('-u'); $benchArgs.Add($Username) }
Write-Host "$Mode -> ${BrokerHost}:$Port; clients=$Clients; MQTT=$MqttVersion; QoS=$Qos; TLS=$([bool]$Tls); duration=${DurationSeconds}s"
if ($Mode -eq 'pub') {
    Write-Host "Payload=${PayloadBytes}B; in-flight/client=$Inflight; interval/client=${IntervalMs}ms; 0 requests maximum speed."
} else { Write-Host 'Each subscriber receives the whole prefix: subscriber count multiplies delivery fan-out.' }
Write-Host 'Observe incoming message rate, drops and queues in the EMQX dashboard.'
if (-not $Run) { Write-Host 'Dry run only. Add -Run to connect and start the benchmark.'; return }

$benchCommand = Get-Command $Binary -CommandType Application -ErrorAction Stop
if ($Username) {
    $benchPassword = $env:EMQTT_BENCH_PASSWORD
    if ($null -eq $benchPassword) { $benchPassword = Read-Host 'MQTT password' -MaskInput }
    $benchArgs.Add('-P'); $benchArgs.Add($benchPassword)
}
$benchStart = [Diagnostics.ProcessStartInfo]::new()
$benchStart.FileName = $benchCommand.Source
$benchStart.UseShellExecute = $false
$benchStart.CreateNoWindow = $true
foreach ($value in $benchArgs) { $benchStart.ArgumentList.Add($value) }
$benchProcess = [Diagnostics.Process]::new()
$benchProcess.StartInfo = $benchStart
$benchStarted = $false
try {
    if (-not $benchProcess.Start()) { throw 'Could not start emqtt_bench.' }
    $benchStarted = $true
    if (-not $benchProcess.WaitForExit($DurationSeconds * 1000)) {
        $benchProcess.Kill($true)
        $benchProcess.WaitForExit()
        Write-Host 'Benchmark duration reached; stopped this benchmark process and its children.'
    } elseif ($benchProcess.ExitCode -ne 0) { throw "emqtt_bench exited with code $($benchProcess.ExitCode)." }
} finally {
    if ($benchStarted -and -not $benchProcess.HasExited) { $benchProcess.Kill($true); $benchProcess.WaitForExit() }
    $benchProcess.Dispose()
}
