#Requires -Version 7.4
<#
    Ad hoc live-tenant connection script -- not part of the shipped module (not in
    build/BuildManifest.psd1, not exported), just a saved copy of the commands used for manual
    connection testing so they don't need to be retyped/repasted each time.

    Prints collector status via a manual per-line loop rather than Format-Table -- Format-Table
    -AutoSize on these nested ordered-dictionary objects rendered as blank columns in testing
    against a real terminal session (data was confirmed present via ConvertTo-Json every time;
    root cause not pinned down, sidestepped rather than chased further since a plain loop is
    just as readable and has no column-width/console-width dependency to go wrong).

    Usage: run from the repo root (where dist/EntraPosture.psd1 lives), e.g.
      pwsh ./scripts/Connect-Tenant.ps1
      pwsh ./scripts/Connect-Tenant.ps1 -Mode FullRun
      pwsh ./scripts/Connect-Tenant.ps1 -Mode FullRun -ArmScope '/subscriptions/<id>'
      pwsh ./scripts/Connect-Tenant.ps1 -AuthMode Certificate -Mode FullRun
#>
[CmdletBinding()]
param (
    [Parameter()]
    [ValidateSet('AccessCheck', 'FullRun')]
    [string]$Mode = 'AccessCheck',

    [Parameter()]
    [ValidateSet('Delegated', 'Certificate')]
    [string]$AuthMode = 'Delegated',

    [Parameter()]
    [string]$TenantId = '<your-tenant-id>',

    [Parameter()]
    [string]$ClientId = '<your-app-registration-client-id>',

    [Parameter()]
    [ValidateSet('Edge', 'Chrome', 'Firefox')]
    [string]$Browser = 'Edge',

    [Parameter()]
    [switch]$NoPrivateBrowsing,

    [Parameter()]
    [string]$PfxPath = "$HOME/.entra-posture-certs/cert.pfx",

    [Parameter()]
    [string]$RunRoot = './runs',

    [Parameter()]
    [string]$ArmScope,

    [Parameter()]
    [switch]$NoOpenReport,

    [Parameter()]
    [switch]$PassThru
)

function Write-CollectorStatusLine {
    param([Parameter(Mandatory)]$Collector)

    $armCollectorNames = @('AzureRoleAssignments', 'AzureSubscriptions', 'AzureManagementGroups', 'AzureRoleDefinitions')
    $color = switch ($Collector.evidenceStatus) {
        'Collected'   { 'Green' }
        'Denied'      { if ($Collector.collectorName -in $armCollectorNames) { 'DarkGray' } else { 'Red' } }
        default       { 'Yellow' }
    }
    $note = if ($Collector.evidenceStatus -eq 'Denied' -and $Collector.collectorName -in $armCollectorNames) { ' (expected -- no ARM token requested/scope not tested)' } else { '' }
    Write-Host ("  {0,-32} {1,-12} requested=[{2}] present=[{3}]{4}" -f `
        $Collector.collectorName, $Collector.evidenceStatus, ($Collector.accessRequested -join ','), ($Collector.rightsPresentInToken -join ','), $note) -ForegroundColor $color
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Import-Module (Join-Path $repoRoot 'dist/EntraPosture.psd1') -Force

$authParams = @{
    TenantId = $TenantId
    ClientId = $ClientId
    AuthMode = $AuthMode
}

if ($AuthMode -eq 'Delegated') {
    $authParams['Browser'] = $Browser
    if (-not $NoPrivateBrowsing) { $authParams['PrivateBrowsing'] = $true }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Starting -- browser is about to open. Default timeout is 300 seconds (5 minutes) before this errors out on its own." -ForegroundColor Cyan
} else {
    if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
        throw "Connect-Tenant.ps1: certificate not found at '$PfxPath'. Pass -PfxPath, or generate one first (see scripts/Connect-Tenant.ps1's own header comment / the Phase 8 setup notes)."
    }
    $pfxPassword = Read-Host -AsSecureString -Prompt "PFX password for $PfxPath"
    $authParams['Certificate'] = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $pfxPassword)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Starting -- certificate app-only, no browser involved." -ForegroundColor Cyan
}

if ($Mode -eq 'AccessCheck') {
    $access = Test-EntraPostureAccess @authParams
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Returned." -ForegroundColor Cyan
    Write-Host ''
    foreach ($collector in $access.collectors) { Write-CollectorStatusLine -Collector $collector }
    Write-Host ''

    $armCollectorNames = @('AzureRoleAssignments', 'AzureSubscriptions', 'AzureManagementGroups', 'AzureRoleDefinitions')
    $realGaps = @($access.collectors | Where-Object { $_.evidenceStatus -eq 'Denied' -and $_.collectorName -notin $armCollectorNames })
    if ($realGaps.Count -gt 0) {
        Write-Host "Real permission gaps (excluding the always-expected 4 ARM entries): $($realGaps.collectorName -join ', ')" -ForegroundColor Yellow
    } else {
        Write-Host "No real permission gaps." -ForegroundColor Green
    }

    if ($PassThru) { return $access }
} else {
    if ($ArmScope) { $authParams['ArmScope'] = $ArmScope }
    $run = Invoke-EntraPosture @authParams -RunRoot $RunRoot
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Returned." -ForegroundColor Cyan
    Write-Host ''

    Write-Host "ExitCode: $($run.ExitCode)"
    Write-Host "HtmlReportPath: $($run.HtmlReportPath)"
    if ($run.Error) { Write-Host "Error: $($run.Error)" -ForegroundColor Red }
    if (-not $ArmScope) { Write-Host "(No -ArmScope supplied -- Azure RBAC collection was skipped entirely, which alone is enough to make this a Partial/ExitCode-3 run.)" -ForegroundColor DarkGray }
    Write-Host ''

    foreach ($collector in $run.Coverage.collectors) { Write-CollectorStatusLine -Collector $collector }

    if (-not $NoOpenReport -and $run.HtmlReportPath -and (Test-Path -LiteralPath $run.HtmlReportPath)) {
        Write-Host ''
        Write-Host "Opening report..." -ForegroundColor Cyan
        $reportPath = (Resolve-Path -LiteralPath $run.HtmlReportPath).Path
        # Start-Process -FilePath <url> works cross-platform (that's what opens the sign-in
        # browser earlier in this script, via .NET's Unix Process.Start special-casing URL
        # schemes) -- but a *local file* path like this HTML report needs actual OS file-type
        # association, which only Windows' ShellExecute integration provides for free. Confirmed
        # directly: on macOS this threw "Permission denied" trying to execute the HTML file as a
        # program rather than open it. macOS needs 'open', Linux needs 'xdg-open'; Windows'
        # existing behavior already works and is left alone.
        if ($IsWindows) {
            Start-Process -FilePath $reportPath | Out-Null
        } elseif ($IsMacOS) {
            Start-Process -FilePath 'open' -ArgumentList $reportPath | Out-Null
        } elseif ($IsLinux) {
            Start-Process -FilePath 'xdg-open' -ArgumentList $reportPath | Out-Null
        } else {
            Write-Host "Could not determine platform to open the report automatically -- open it manually: $reportPath" -ForegroundColor Yellow
        }
    }

    if ($PassThru) { return $run }
}
