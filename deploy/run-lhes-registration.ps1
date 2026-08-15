<#
Runs the three LHES registration loaders in the required order.

Keep this file, all-meters.csv, and the three load-lhes-*.ps1 files in the
same folder. Run from that folder:
  powershell -ExecutionPolicy Bypass -File .\run-lhes-registration.ps1
#>

$ErrorActionPreference = 'Stop'
$scriptDirectory = $PSScriptRoot
$csv = Join-Path $scriptDirectory 'all-meters.csv'
$loaders = @(
    'load-lhes-meters.ps1',
    'load-lhes-security.ps1',
    'load-lhes-latestrouting.ps1'
)

if (-not (Test-Path -LiteralPath $csv)) {
    throw "CSV not found: $csv"
}
foreach ($loader in $loaders) {
    $path = Join-Path $scriptDirectory $loader
    if (-not (Test-Path -LiteralPath $path)) { throw "Loader not found: $path" }
}

$originalPassword = $env:LHES_SQL_PASSWORD
try {
    if ([string]::IsNullOrWhiteSpace($env:LHES_SQL_PASSWORD)) {
        $securePassword = Read-Host 'LHES SQL password' -AsSecureString
        $env:LHES_SQL_PASSWORD = [System.Net.NetworkCredential]::new('', $securePassword).Password
    }

    foreach ($loader in $loaders) {
        Write-Host "`n===== Running $loader =====" -ForegroundColor Cyan
        & (Join-Path $scriptDirectory $loader)
        $loaderSucceeded = $?
        if (-not $loaderSucceeded) { throw "$loader failed." }
    }

    Write-Host "`nLHES registration completed successfully." -ForegroundColor Green
}
finally {
    $env:LHES_SQL_PASSWORD = $originalPassword
}
