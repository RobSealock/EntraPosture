#Requires -Version 7.4
<#
    Ad hoc live What-If comparison script -- not part of the shipped module. Authenticates,
    collects live Conditional Access policies fresh, runs the same scenario through both this
    project's offline simulation engine and Microsoft's real What-If API, and prints the
    per-policy agreement/disagreement comparison (engineering plan WS4 task 10).

    The functions this script calls (the CA collector, the simulation engine,
    Invoke-EntraPostureWhatIfEvaluation, Compare-EntraPostureWhatIfResult) are internal to
    the module, not exported -- this script reaches into the module's own session state via
    `& (Get-Module EntraPosture) { ... }` to call them directly against the real built dist/
    artifact, the same technique tests/Contract/BuildDeterminism.Tests.ps1 already established
    for testing private module functions.

    Usage: pwsh ./scripts/Compare-WhatIf.ps1
#>
[CmdletBinding()]
param (
    [Parameter()]
    [ValidateSet('Delegated', 'Certificate')]
    [string]$AuthMode = 'Certificate',

    [Parameter()]
    [string]$TenantId = '<your-tenant-id>',

    [Parameter()]
    [string]$ClientId = '<your-app-registration-client-id>',

    [Parameter()]
    [string]$UserId = '<your-user-object-id>',

    [Parameter()]
    [string]$ApplicationId = '00000003-0000-0ff1-ce00-000000000000',

    [Parameter()]
    [ValidateSet('android', 'iOS', 'windows', 'windowsPhone', 'macOS', 'linux', 'all')]
    [string]$Platform = 'windows',

    [Parameter()]
    [ValidateSet('all', 'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other')]
    [string]$ClientAppType = 'browser',

    [Parameter()]
    [ValidateSet('Edge', 'Chrome', 'Firefox')]
    [string]$Browser = 'Edge',

    [Parameter()]
    [switch]$NoPrivateBrowsing,

    [Parameter()]
    [string]$PfxPath = "$HOME/.entra-posture-certs/cert.pfx"
)

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Import-Module (Join-Path $repoRoot 'dist/EntraPosture.psd1') -Force
$module = Get-Module EntraPosture

# Authenticate outside the module scriptblock (Connect-EntraPostureCertificate/Delegated are
# also internal, so this itself runs through the module too) -- kept as its own step so an
# auth failure produces a clear error before anything else runs.
$graphToken = & $module {
    param($AuthMode, $TenantId, $ClientId, $PfxPath, $Browser, $PrivateBrowsing)
    $tokenCache = New-EntraPostureTokenCache
    $graphScope = 'https://graph.microsoft.com/.default'
    if ($AuthMode -eq 'Certificate') {
        if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
            throw "Compare-WhatIf.ps1: certificate not found at '$PfxPath'."
        }
        $pfxPassword = Read-Host -AsSecureString -Prompt "PFX password for $PfxPath"
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $pfxPassword)
        $result = Connect-EntraPostureCertificate -ClientId $ClientId -TenantId $TenantId -Certificate $cert -Scope $graphScope -TokenCache $tokenCache
    } else {
        $result = Connect-EntraPostureDelegated -ClientId $ClientId -TenantId $TenantId -Scope $graphScope -TokenCache $tokenCache -Browser $Browser -PrivateBrowsing:$PrivateBrowsing
    }
    return $result.AccessToken
} $AuthMode $TenantId $ClientId $PfxPath $Browser ([bool](-not $NoPrivateBrowsing))

Write-Host "Authenticated. Collecting live Conditional Access policies..." -ForegroundColor Cyan

$comparison = & $module {
    param($GraphToken, $UserId, $ApplicationId, $Platform, $ClientAppType)

    $collectorResult = Invoke-EntraPostureConditionalAccessPolicyCollector -AccessToken $GraphToken -TenantScope 'compare-whatif'
    $policies = @($collectorResult.Entities)
    Write-Host "Collected $($policies.Count) Conditional Access policy object(s) from the tenant." -ForegroundColor Cyan

    $scenario = New-EntraPostureConditionalAccessScenario -UserId $UserId -ApplicationId $ApplicationId -ClientAppType $ClientAppType -Platform $Platform

    $localResult = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario $scenario

    Write-Host "Calling the live What-If API..." -ForegroundColor Cyan
    $liveResults = Invoke-EntraPostureWhatIfEvaluation -AccessToken $GraphToken -UserId $UserId -ApplicationId $ApplicationId -ClientAppType $ClientAppType -Platform $Platform

    return Compare-EntraPostureWhatIfResult -LocalScenarioResult $localResult -LiveWhatIfResults $liveResults
} $graphToken $UserId $ApplicationId $Platform $ClientAppType

Write-Host ''
Write-Host "Agreement: $($comparison.AgreementCount)  Disagreement: $($comparison.DisagreementCount)" -ForegroundColor $(if ($comparison.DisagreementCount -eq 0) { 'Green' } else { 'Yellow' })
Write-Host ''

if ($comparison.Comparisons.Count -eq 0) {
    Write-Host "No policies on either side to compare -- the tenant currently has zero Conditional Access policies." -ForegroundColor DarkGray
} else {
    foreach ($entry in $comparison.Comparisons) {
        $color = if ($entry.Agrees) { 'Green' } else { 'Yellow' }
        Write-Host ("  {0,-40} local={1,-6} live={2,-6} reason={3,-20} agrees={4}" -f `
            $entry.PolicyId, $entry.LocalApplies, $entry.LiveApplies, $entry.LiveAnalysisReason, $entry.Agrees) -ForegroundColor $color
    }
}
