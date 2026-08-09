<#
.SYNOPSIS
    Assigns (or removes) simulated meter IPv6 addresses on a local adapter, so on-demand push
    can bind each meter's OWN source address while testing on Windows.

.DESCRIPTION
    Linux owns the whole meter prefix with a single `ip -6 route add local <prefix>`. Windows has
    no equivalent, so each meter address must be assigned to an adapter individually — which is
    why binding fails on a dev box until you run this. Practical for tens of meters, not thousands.

    Addresses are computed with the SAME math as MeterAddressing.ComputeAddress (meter index in
    the low 48 bits), so the script and the app can never disagree.

    REQUIRES AN ELEVATED (Administrator) PowerShell.

.EXAMPLE
    # Add meters for batch StartIndex=1 Count=1, plus a stand-in head-end
    .\push-test-addresses.ps1 -StartIndex 1 -Count 1

.EXAMPLE
    # Clean up afterwards
    .\push-test-addresses.ps1 -Remove
#>
param(
    [string]$InterfaceAlias = "Wi-Fi",
    [string]$Prefix         = "fd00:6d65:7472::",
    [long]  $StartIndex     = 1,
    [long]  $Count          = 1,
    # Stand-in "head-end" address to push AT. Must be outside the meter range above.
    [long]  $HeadEndIndex   = 65535,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

# ── Elevation check ───────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must run in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
    Write-Host "Relaunch with:" -ForegroundColor Yellow
    Write-Host "  Start-Process powershell -Verb RunAs -ArgumentList '-NoExit','-File','$PSCommandPath'"
    exit 1
}

# Mirrors MeterAddressing.ComputeAddress: meter index occupies the low 48 bits (bytes 10..15).
function Get-MeterAddress {
    param([string]$PrefixBase, [long]$Index)
    $bytes = ([System.Net.IPAddress]::Parse($PrefixBase)).GetAddressBytes()
    for ($i = 0; $i -lt 6; $i++) {
        $bytes[10 + $i] = [byte](($Index -shr (40 - 8 * $i)) -band 0xFF)
    }
    return ([System.Net.IPAddress]::new($bytes)).IPAddressToString
}

# ── Removal ───────────────────────────────────────────────────────────────────
if ($Remove) {
    $base = $Prefix.TrimEnd(':')
    $existing = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -like "$base*" }

    if (-not $existing) { Write-Host "No addresses matching '$base*' found." -ForegroundColor Cyan; exit 0 }

    foreach ($a in $existing) {
        Write-Host ("  removing {0} ({1})" -f $a.IPAddress, $a.InterfaceAlias)
        Remove-NetIPAddress -IPAddress $a.IPAddress -InterfaceIndex $a.InterfaceIndex -Confirm:$false
    }
    Write-Host "Removed $($existing.Count) address(es)." -ForegroundColor Green
    exit 0
}

# ── Validation ────────────────────────────────────────────────────────────────
if (-not (Get-NetAdapter -Name $InterfaceAlias -ErrorAction SilentlyContinue)) {
    Write-Host "No adapter named '$InterfaceAlias'. Available:" -ForegroundColor Red
    Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, Status | Format-Table -AutoSize
    exit 1
}

$endIndex = $StartIndex + $Count - 1
if ($HeadEndIndex -ge $StartIndex -and $HeadEndIndex -le $endIndex) {
    Write-Host "HeadEndIndex $HeadEndIndex collides with the meter range $StartIndex..$endIndex." -ForegroundColor Red
    exit 1
}

# ── Assign ────────────────────────────────────────────────────────────────────
Write-Host "Adapter '$InterfaceAlias'  prefix '$Prefix'" -ForegroundColor Cyan
Write-Host "Meters: index $StartIndex..$endIndex" -ForegroundColor Cyan
Write-Host ""

$added = 0
foreach ($index in $StartIndex..$endIndex) {
    $addr = Get-MeterAddress -PrefixBase $Prefix -Index $index
    try {
        New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $addr -PrefixLength 64 | Out-Null
        Write-Host ("  meter {0,-8} {1}" -f $index, $addr) -ForegroundColor Green
        $added++
    } catch {
        Write-Host ("  meter {0,-8} {1}   (already present)" -f $index, $addr) -ForegroundColor DarkGray
    }
}

$headEnd = Get-MeterAddress -PrefixBase $Prefix -Index $HeadEndIndex
try {
    New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $headEnd -PrefixLength 64 | Out-Null
    Write-Host ("  head-end          {0}" -f $headEnd) -ForegroundColor Green
} catch {
    Write-Host ("  head-end          {0}   (already present)" -f $headEnd) -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Done ($added new). Windows may hold addresses in 'Tentative' for a few seconds." -ForegroundColor Cyan
Write-Host ""
Write-Host "Next:" -ForegroundColor Yellow
Write-Host "  1. Listener:      .\deploy\push-listener.ps1 -Port 9999"
Write-Host "  2. Dashboard push IP box:   [$headEnd]:9999"
Write-Host "  3. Expect $Count connection(s), sources $((Get-MeterAddress $Prefix $StartIndex)) .. $((Get-MeterAddress $Prefix $endIndex))"
Write-Host ""
Write-Host "  Cleanup:          .\deploy\push-test-addresses.ps1 -Remove"
