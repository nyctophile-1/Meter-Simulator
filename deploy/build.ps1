<#
.SYNOPSIS
    Build the Linux deployment artifact: publish/maya-sim.tar.gz

.DESCRIPTION
    Runs tests, publishes self-contained linux-x64, injects the production config,
    packages the tarball, and verifies it. Stops on the first failure so a broken
    build can never be packaged over a stale one.

.EXAMPLE
    .\deploy\build.ps1 -Target eqa
    .\deploy\build.ps1 -Target personal
    .\deploy\build.ps1 -Target eqa -SkipTests
#>
[CmdletBinding()]
param(
    # Which deployment this artifact is for. The two differ only in config — the IPv6 meter
    # prefix delegated to that instance's ENI, and the host you ship it to. There is no default
    # on purpose: silently building for the wrong instance produces meters that look fine in the
    # UI and are unreachable from the HES.
    [Parameter(Mandatory)]
    [ValidateSet('eqa', 'personal')]
    [string]$Target,

    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'

# Per-target facts. Everything that differs between the two deployments lives here, so adding a
# third target is one entry rather than a hunt through the script.
$Targets = @{
    eqa = @{
        ConfigFile = 'appsettings.eqa.json'
        Prefix     = '2406:da1a:261:6903:882d::/80'
        # Org-account instance i-0587520c9767568a1. SSH over IPv4: this ENI is prefix-only, so
        # it has no global IPv6 address of its own to connect to.
        SshHost    = '15.252.116.146'
    }
    personal = @{
        ConfigFile = 'appsettings.personal.json'
        Prefix     = '2406:da1a:1c29:500:bc96::/80'
        SshHost    = '[2406:da1a:1c29:500::65f5]'
    }
}

$T              = $Targets[$Target]
$ExpectedPrefix = $T.Prefix

$Root       = Split-Path -Parent $PSScriptRoot
$Project    = Join-Path $Root 'ManyMeterSimulator\ManyMeterSimulator\ManyMeterSimulator.csproj'
$TestProj   = Join-Path $Root 'ManyMeterSimulator\ManyMeterSimulator.Tests\ManyMeterSimulator.Tests.csproj'
$OutDir     = Join-Path $Root 'publish\linux-x64'
$Tarball    = Join-Path $Root 'publish\maya-sim.tar.gz'
$ConfigSrc  = Join-Path $PSScriptRoot $T.ConfigFile

# The app runs with no DOTNET_ENVIRONMENT set, so it loads appsettings.Production.json. The
# target picks which source file lands under that name — deploy.sh and the systemd unit stay
# identical for both.
$ConfigDest = Join-Path $OutDir 'appsettings.Production.json'

Write-Host "Target: $Target  ($($T.ConfigFile) -> appsettings.Production.json)" -ForegroundColor Magenta

function Step($n, $msg) { Write-Host "`n[$n] $msg" -ForegroundColor Cyan }
function Die($msg)       { Write-Host "`nFAILED: $msg" -ForegroundColor Red; exit 1 }

Push-Location $Root
try {
    # ── 1. Tests ──────────────────────────────────────────────────────────────
    if (-not $SkipTests) {
        Step 1 'Running tests'
        dotnet test $TestProj -c Release --nologo --verbosity quiet
        if ($LASTEXITCODE -ne 0) { Die 'Tests failed. Nothing was packaged.' }
    } else {
        Step 1 'Skipping tests (-SkipTests)'
    }

    # ── 2. Clean ──────────────────────────────────────────────────────────────
    Step 2 'Clearing previous output'
    if (Test-Path $OutDir)  { Remove-Item -Recurse -Force $OutDir }
    if (Test-Path $Tarball) { Remove-Item -Force $Tarball }

    # ── 3. Publish ────────────────────────────────────────────────────────────
    # Self-contained: the .NET runtime ships inside the folder, so the server needs
    # no runtime installed. linux-x64 because the instance is Ubuntu on x86_64.
    Step 3 'Publishing self-contained linux-x64'
    dotnet publish $Project -c Release -r linux-x64 --self-contained true -o $OutDir --nologo --verbosity quiet
    if ($LASTEXITCODE -ne 0) { Die 'Publish failed.' }
    if (-not (Test-Path (Join-Path $OutDir 'ManyMeterSimulator'))) { Die 'Publish produced no Linux apphost.' }

    # ── 4. Production config ──────────────────────────────────────────────────
    # Not part of the project, so neither `dotnet publish` nor VS copies it. Without
    # it the app falls back to appsettings.json and its fd00: dev-default prefix.
    Step 4 "Injecting $($T.ConfigFile) as appsettings.Production.json"
    if (-not (Test-Path $ConfigSrc)) { Die "Missing $ConfigSrc" }

    # Provenance: the file must declare the target it is being built for. Guards against copying
    # one config over the other and shipping EQA's prefix to the personal box, or vice versa.
    $declared = Select-String -Path $ConfigSrc -Pattern '"DeployTarget"\s*:\s*"([^"]+)"'
    if (-not $declared) { Die "$($T.ConfigFile) has no DeployTarget marker." }
    $declaredTarget = $declared.Matches[0].Groups[1].Value
    if ($declaredTarget -ne $Target) {
        Die "$($T.ConfigFile) declares DeployTarget '$declaredTarget' but -Target is '$Target'."
    }

    $prefixLine = Select-String -Path $ConfigSrc -Pattern 'AddressPrefix'
    if ($prefixLine -notmatch [regex]::Escape($ExpectedPrefix)) {
        Die "$($T.ConfigFile) prefix does not match the '$Target' target ($ExpectedPrefix).`n       Found: $($prefixLine.Line.Trim())"
    }

    Copy-Item $ConfigSrc $ConfigDest -Force
    Write-Host "      target OK: $Target"
    Write-Host "      prefix OK: $ExpectedPrefix"

    # ── 5. Package ────────────────────────────────────────────────────────────
    Step 5 'Creating tarball'
    tar -czf $Tarball -C $OutDir .
    if ($LASTEXITCODE -ne 0) { Die 'tar failed.' }

    # ── 6. Verify ─────────────────────────────────────────────────────────────
    Step 6 'Verifying'
    $entries = tar -tzf $Tarball
    foreach ($required in @('./ManyMeterSimulator', './appsettings.Production.json')) {
        if ($entries -notcontains $required) { Die "Tarball is missing $required" }
    }
    $templates = ($entries | Where-Object { $_ -like './Templates/*.xml' }).Count
    if ($templates -lt 1) { Die 'Tarball contains no meter templates.' }

    $sizeMb = [math]::Round((Get-Item $Tarball).Length / 1MB, 1)
    if ($sizeMb -lt 30) { Die "Tarball is only ${sizeMb} MB - publish looks incomplete." }

    Write-Host "`nBuilt $Tarball  for '$Target'  (${sizeMb} MB, $templates templates)" -ForegroundColor Green
    Write-Host "`nNext:" -ForegroundColor Yellow
    Write-Host '  $KEY = "C:\Users\ayush\OneDrive\Documents\Development\Sinhal Repos\all_creds\maya-sim-test.pem"'
    Write-Host '  cd "C:\Users\ayush\OneDrive\Documents\Development\Sinhal Repos\Meter-Simulator"'
    Write-Host "  scp -i `$KEY publish\maya-sim.tar.gz deploy\host-prep.sh deploy\deploy.sh ubuntu@$($T.SshHost):/tmp/"
    Write-Host "  ssh -i `$KEY ubuntu@$($T.SshHost)"
    # host-prep takes the prefix as an argument now, so the host route always matches the
    # config that shipped with this tarball.
    Write-Host "  sudo bash /tmp/host-prep.sh $ExpectedPrefix    # first deployment only"
    Write-Host '  sudo bash /tmp/deploy.sh /tmp/maya-sim.tar.gz'
}
finally {
    Pop-Location
}
