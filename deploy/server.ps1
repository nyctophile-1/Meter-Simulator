<#
.SYNOPSIS
    Start, stop or inspect the simulator's EC2 instance.

.DESCRIPTION
    Wraps the handful of AWS CLI calls needed to bring the simulator host up and down, and waits
    for the transition to finish so the script exits only when the instance has actually reached
    the state you asked for.

    CREDENTIALS ARE NEVER STORED HERE. The AWS CLI keeps them in %USERPROFILE%\.aws\credentials
    (put there by `aws configure`); this script simply invokes the CLI and inherits them. Use
    -Profile if you keep more than one set.

.EXAMPLE
    .\deploy\server.ps1 status
    .\deploy\server.ps1 start
    .\deploy\server.ps1 stop
    .\deploy\server.ps1 stop -Force
    .\deploy\server.ps1 restart -Target eqa
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('status', 'start', 'stop', 'restart')]
    [string]$Action,

    [ValidateSet('eqa', 'personal')]
    [string]$Target = 'eqa',

    # Skip the confirmation prompt on stop/restart. For unattended use only.
    [switch]$Force,

    # Named profile from ~/.aws/credentials, when more than one account is configured.
    [string]$AwsProfile,

    # After start, poll the dashboard until it answers. "running" is not the same as "usable".
    [int]$ReadyTimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'

# Per-target facts, mirroring build.ps1 so a third environment is one entry in both files.
# The instance id is not a secret; the credentials that can act on it are, and they live outside
# the repo.
$Targets = @{
    eqa = @{
        InstanceId = 'i-0587520c9767568a1'
        Region     = 'ap-south-1'
        # What build.ps1 currently hardcodes as SshHost. Compared against the live address after
        # every start so a changed public IP is reported rather than silently breaking scp/ssh.
        ExpectedIp = '15.252.116.146'
    }
    personal = @{
        InstanceId = ''
        Region     = 'ap-south-1'
        ExpectedIp = ''
    }
}

$T = $Targets[$Target]

function Info($m) { Write-Host $m }
function Good($m) { Write-Host $m -ForegroundColor Green }
function Warn($m) { Write-Host $m -ForegroundColor Yellow }
function Die($m) { Write-Host "`nFAILED: $m" -ForegroundColor Red; exit 1 }
function Step($m) { Write-Host "`n$m" -ForegroundColor Cyan }

if ([string]::IsNullOrWhiteSpace($T.InstanceId)) {
    Die "No instance id configured for target '$Target'. Add it to the `$Targets table in $PSCommandPath."
}

# Common arguments for every call: the region is pinned rather than inherited, so a changed
# profile default cannot silently aim these commands at an empty region.
$Common = @('--region', $T.Region)
if ($AwsProfile) { $Common += @('--profile', $AwsProfile) }

# Every AWS call goes through here.
#
# Windows PowerShell wraps a native command's stderr in an ErrorRecord when you redirect it, and
# with $ErrorActionPreference = 'Stop' that becomes TERMINATING even when the exe succeeded. So
# stderr is captured with the preference relaxed, and success is judged only by the exit code --
# which is the exe's actual verdict. -AllowFail lets a caller treat a non-zero exit as an answer
# (e.g. "no permission to check that") rather than a failure.
function Invoke-Aws {
    param([string[]]$CliArgs, [switch]$AllowFail)

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = (& $AwsExe @CliArgs @Common 2>&1 | Out-String)
    $script:LastAwsExit = $LASTEXITCODE
    $ErrorActionPreference = $prev

    if ($script:LastAwsExit -ne 0 -and -not $AllowFail) {
        Die "aws $($CliArgs -join ' ') failed (exit $script:LastAwsExit)`n$($out.Trim())"
    }
    return $out.Trim()
}

function Get-State {
    (Invoke-Aws @('ec2', 'describe-instances', '--instance-ids', $T.InstanceId,
           '--query', 'Reservations[0].Instances[0].State.Name', '--output', 'text')).Trim()
}

function Get-PublicIp {
    $ip = (Invoke-Aws @('ec2', 'describe-instances', '--instance-ids', $T.InstanceId,
                 '--query', 'Reservations[0].Instances[0].PublicIpAddress', '--output', 'text')).Trim()
    if ($ip -eq 'None' -or [string]::IsNullOrWhiteSpace($ip)) { return $null }
    return $ip
}

# True when the public address is an Elastic IP â€” i.e. it survives a stop/start. Reported rather
# than assumed, because it decides whether the hardcoded SshHost can be trusted.
# Answers "unknown" as $null rather than guessing: the start/stop role may not carry
# ec2:DescribeAddresses, and "I could not check" must not be reported as "not elastic".
function Test-ElasticIp {
    param([string]$Ip)
    if (-not $Ip) { return $null }
    Invoke-Aws @('ec2', 'describe-addresses', '--public-ips', $Ip, '--output', 'text') -AllowFail | Out-Null
    if ($script:LastAwsExit -eq 0) { return $true }
    # A genuine "this is not an EIP" is InvalidAddress.NotFound; anything else (typically
    # UnauthorizedOperation) means we simply do not know.
    return $null
}

# â”€â”€ Preflight â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
$AwsExe = (Get-Command aws -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $AwsExe) {
    Die "AWS CLI not found. Install it from https://aws.amazon.com/cli/ and run `aws configure`."
}

$whoami = Invoke-Aws @('sts', 'get-caller-identity', '--query', 'Arn', '--output', 'text') -AllowFail
if ($script:LastAwsExit -ne 0) {
    Die "AWS credentials are not working (expired or wrong profile?).`n$whoami`nRun: aws configure"
}

Info "Target      : $Target"
Info "Instance    : $($T.InstanceId)  ($($T.Region))"
Info "Identity    : $($whoami.Trim())"

$state = Get-State
Info "State       : $state"

# â”€â”€ Reporting helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function Report-Address {
    $ip = Get-PublicIp
    if (-not $ip) { Warn "No public IPv4 assigned."; return }

    $elastic = Test-ElasticIp -Ip $ip
    Info ""
    Good "Public IPv4 : $ip$(if ($elastic -eq $true) { '  (Elastic IP - stable across restarts)' })"
    Info  "Dashboard   : http://$ip/"

    if ($T.ExpectedIp -and $ip -ne $T.ExpectedIp) {
        Warn ""
        Warn "The public IP CHANGED: build.ps1 still expects $($T.ExpectedIp)."
        Warn "Until it is updated, scp/ssh to this host will target an address that no longer exists."
        Warn "Fix: set SshHost = '$ip' for the '$Target' target in deploy\build.ps1."
    }
    elseif ($null -eq $elastic) {
        Info ""
        Info "Could not check whether this is an Elastic IP (no ec2:DescribeAddresses permission)."
        Info "If it is not, the address can change on the next stop/start - this script compares it"
        Info "against build.ps1 each time, so a change will be reported here."
    }

    # The delegated IPv6 prefix is an ENI attribute and survives stop/start, so meter addressing
    # and the host-prep local route are unaffected â€” the route unit re-applies at boot.
    Info "Meter IPv6 prefix is unaffected by a restart (ENI attribute, route unit re-applies on boot)."
}

function Wait-Ready {
    param([string]$Ip)
    if (-not $Ip) { return }

    Step "Waiting for the dashboard to answer (up to ${ReadyTimeoutSeconds}s)"
    $deadline = (Get-Date).AddSeconds($ReadyTimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri "http://$Ip/" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            if ($r.StatusCode -ge 200) { Good "Dashboard is up (HTTP $($r.StatusCode))."; return }
        }
        catch {
            # A refused connection or redirect-to-login both mean the host is reachable; only a
            # total timeout means it is still booting.
            if ($_.Exception.Response) { Good "Dashboard is up (HTTP $([int]$_.Exception.Response.StatusCode))."; return }
        }
        Start-Sleep -Seconds 5
    }
    Warn "Instance is running but the dashboard did not answer within ${ReadyTimeoutSeconds}s."
    Warn "The service may still be starting: ssh in and check 'systemctl status maya-sim'."
}

function Confirm-Stop {
    if ($Force) { return $true }
    Warn ""
    Warn "This stops the SHARED $Target instance - anyone mid-test will lose the running simulator."
    $answer = Read-Host "Type the target name ('$Target') to confirm"
    if ($answer -ne $Target) { Info "Cancelled."; return $false }
    return $true
}

function Do-Start {
    if ($state -eq 'running') {
        Good "Already running - nothing to do."
        Report-Address
        return
    }
    if ($state -notin @('stopped', 'stopping')) {
        Die "Cannot start from state '$state'. Wait for it to settle and try again."
    }

    Step "Starting $($T.InstanceId)"
    Invoke-Aws @('ec2', 'start-instances', '--instance-ids', $T.InstanceId, '--output', 'text') | Out-Null

    Info "Waiting for state 'running'..."
    Invoke-Aws @('ec2', 'wait', 'instance-running', '--instance-ids', $T.InstanceId) | Out-Null
    Good "Instance is running."

    $ip = Get-PublicIp
    Report-Address
    Wait-Ready -Ip $ip
}

function Do-Stop {
    if ($state -eq 'stopped') { Good "Already stopped - nothing to do."; return $true }
    if ($state -notin @('running', 'pending')) {
        Die "Cannot stop from state '$state'. Wait for it to settle and try again."
    }
    if (-not (Confirm-Stop)) { return $false }

    Step "Stopping $($T.InstanceId)"
    Invoke-Aws @('ec2', 'stop-instances', '--instance-ids', $T.InstanceId, '--output', 'text') | Out-Null

    Info "Waiting for state 'stopped'..."
    Invoke-Aws @('ec2', 'wait', 'instance-stopped', '--instance-ids', $T.InstanceId) | Out-Null
    Good "Instance is stopped. (No compute charges while stopped; EBS storage still bills.)"
    return $true
}

switch ($Action) {
    'status' {
        Report-Address
    }
    'start' {
        Do-Start
    }
    'stop' {
        Do-Stop | Out-Null
    }
    'restart' {
        if (Do-Stop) {
            $state = Get-State
            Do-Start
        }
    }
}


