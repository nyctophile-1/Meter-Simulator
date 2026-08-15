<#
Runs the three EHES registration loaders in the required order.

Keep this file, all-meters.csv, and the three load-*.ps1 files in the
same folder. Run from that folder:
  powershell -ExecutionPolicy Bypass -File .\run-ehes-registration.ps1
#>

$ErrorActionPreference = 'Stop'
$scriptDirectory = $PSScriptRoot
$csv = Join-Path $scriptDirectory 'all-meters.csv'
$loaders = @(
    'load-meters.ps1',
    'load-security.ps1',
    'load-latestrouting.ps1'
)

if (-not (Test-Path -LiteralPath $csv)) {
    throw "CSV not found: $csv"
}
foreach ($loader in $loaders) {
    $path = Join-Path $scriptDirectory $loader
    if (-not (Test-Path -LiteralPath $path)) { throw "Loader not found: $path" }
}

$originalPassword = $env:EHES_SQL_PASSWORD
try {
    if ([string]::IsNullOrWhiteSpace($env:EHES_SQL_PASSWORD)) {
        $securePassword = Read-Host 'EHES SQL password' -AsSecureString
        $env:EHES_SQL_PASSWORD = [System.Net.NetworkCredential]::new('', $securePassword).Password
    }

    foreach ($loader in $loaders) {
        Write-Host "`n===== Running $loader =====" -ForegroundColor Cyan
        & (Join-Path $scriptDirectory $loader)
        $loaderSucceeded = $?
        if (-not $loaderSucceeded) { throw "$loader failed." }
    }

    Write-Host "`nEHES registration completed successfully." -ForegroundColor Green
}
finally {
    $env:EHES_SQL_PASSWORD = $originalPassword
}
