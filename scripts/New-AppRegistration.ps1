#Requires -Version 7.4
<#
    One-time bootstrap script: creates the app registration this tool's delegated auth mode
    needs, using Azure CLI -- not part of the shipped module, not something the assessment tool
    itself does (this tool has no write-permission code path anywhere; NOTICE.md states "no
    write operation exists anywhere in this codebase" and this script deliberately stays outside
    that boundary rather than weakening it).

    Deliberately built on Azure CLI (`az login` / `az ad app ...`), not a first-party client ID
    silently reused by this project's own code. The distinction matters and is the whole reason
    this script exists as a separate, explicit, user-initiated step rather than being baked into
    the tool: `az login` uses Azure CLI's own well-known public client ID, transparently, with
    sign-in activity accurately attributed to "Azure CLI" in your tenant's logs -- you are
    genuinely using Azure CLI, a real Microsoft admin tool, for exactly the purpose it exists
    for (managing your own tenant's app registrations). That is categorically different from
    EntraFalcon's default 'BroCi' auth flow, which reuses a *stored refresh token* for the Azure
    Portal's client ID to make *this tool's own ongoing data-collection calls* look like Azure
    Portal activity -- disguising a third-party tool's actual behavior behind a first-party
    identity it was never authorized for that purpose, not a one-time transparent admin action.
    See README.md's "Why an app registration, and why not skip it" section for the full
    reasoning this script is the practical antidote to.

    Requires: Azure CLI installed and you signed in as a user who can create app registrations
    and grant admin consent (Application Administrator, Cloud Application Administrator, or
    Global Administrator for the consent step specifically).

    Usage: pwsh ./scripts/New-AppRegistration.ps1 -TenantId '<tenant-id>'
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter()]
    [string]$DisplayName = 'EntraPosture',

    [Parameter()]
    [switch]$SkipAdminConsent
)

$ErrorActionPreference = 'Stop'

# The 12 Microsoft Graph delegated permissions this tool's collectors declare -- see
# docs/PermissionMatrix.md, generated directly from src/Collectors/*.ps1's own RequiredPermissions.
$requiredScopes = @(
    'Policy.Read.All'
    'RoleManagement.Read.Directory'
    'User.Read.All'
    'Group.Read.All'
    'GroupMember.Read.All'
    'Application.Read.All'
    'AdministrativeUnit.Read.All'
    'AccessReview.Read.All'
    'AuthenticationContext.Read.All'
    'Organization.Read.All'
    'Policy.Read.AuthenticationMethod'
    'RoleManagementPolicy.Read.Directory'
)

$graphAppId = '00000003-0000-0000-c000-000000000000'  # Microsoft Graph's own well-known application ID -- a fixed, documented constant, not tenant-specific.

function Test-AzCliAvailable {
    if (-not (Get-Command -Name az -ErrorAction SilentlyContinue)) {
        throw 'New-AppRegistration.ps1: Azure CLI (az) is not installed or not on PATH.'
    }
}

function Confirm-AzLogin {
    param([string]$TenantId)
    $account = az account show --query 'tenantId' -o tsv 2>$null
    if (-not $account -or $account -ne $TenantId) {
        Write-Host "Signing in to tenant $TenantId via Azure CLI (accurately attributed as 'Azure CLI' in your sign-in logs)..." -ForegroundColor Cyan
        az login --tenant $TenantId --allow-no-subscriptions | Out-Null
    } else {
        Write-Host "Already signed in to tenant $TenantId via Azure CLI." -ForegroundColor Cyan
    }
}

Test-AzCliAvailable
Confirm-AzLogin -TenantId $TenantId

Write-Host "`nResolving Microsoft Graph's own delegated-permission scope IDs (dynamically, not hardcoded -- these are stable but this avoids trusting a possibly-stale GUID list)..." -ForegroundColor Cyan
$allScopesJson = az ad sp show --id $graphAppId --query 'oauth2PermissionScopes' -o json
$allScopes = $allScopesJson | ConvertFrom-Json

$resolvedScopes = [System.Collections.Generic.List[string]]::new()
$missingScopes = [System.Collections.Generic.List[string]]::new()
foreach ($scopeName in $requiredScopes) {
    $match = $allScopes | Where-Object { $_.value -eq $scopeName } | Select-Object -First 1
    if (-not $match) {
        $missingScopes.Add($scopeName)
        continue
    }
    $resolvedScopes.Add("$($match.id)=Scope")
}
if ($missingScopes.Count -gt 0) {
    throw "New-AppRegistration.ps1: could not resolve the following permission name(s) against Microsoft Graph's current scope list -- names may have changed: $($missingScopes -join ', ')"
}
Write-Host "Resolved all $($resolvedScopes.Count) permission scopes." -ForegroundColor Green

Write-Host "`nCreating app registration '$DisplayName'..." -ForegroundColor Cyan
$app = az ad app create --display-name $DisplayName --sign-in-audience AzureADMyOrg | ConvertFrom-Json
$clientId = $app.appId
Write-Host "Created. Application (client) ID: $clientId" -ForegroundColor Green

Write-Host "`nConfiguring the public-client redirect URI (http://localhost, for delegated interactive auth -- see LoopbackListener.ps1's own reasoning for why this exact hostname, not 127.0.0.1)..." -ForegroundColor Cyan
az ad app update --id $clientId --public-client-redirect-uris 'http://localhost' | Out-Null

Write-Host "`nAdding the $($resolvedScopes.Count) required Graph delegated permissions..." -ForegroundColor Cyan
# --api-permissions takes multiple separate 'guid=Scope' arguments, not one space-joined string --
# passing the array directly lets PowerShell expand it into separate argv entries for the
# external az process, which -join ' ' into a single string would not do correctly.
az ad app permission add --id $clientId --api $graphAppId --api-permissions $resolvedScopes | Out-Null

if ($SkipAdminConsent) {
    Write-Host "`n-SkipAdminConsent supplied. Permissions were added but not consented -- someone with Application Administrator, Cloud Application Administrator, or Global Administrator will need to run:" -ForegroundColor Yellow
    Write-Host "  az ad app permission admin-consent --id $clientId"
} else {
    Write-Host "`nGranting admin consent (requires Application Administrator, Cloud Application Administrator, or Global Administrator)..." -ForegroundColor Cyan
    try {
        az ad app permission admin-consent --id $clientId
        Write-Host "Admin consent granted." -ForegroundColor Green
    } catch {
        Write-Host "Admin consent failed -- your signed-in account likely doesn't hold a sufficient role. Ask an admin to run:" -ForegroundColor Yellow
        Write-Host "  az ad app permission admin-consent --id $clientId"
    }
}

Write-Host "`n=== Done. This is a one-time, org-wide setup -- save these for every future run: ===" -ForegroundColor Green
Write-Host "TenantId: $TenantId"
Write-Host "ClientId: $clientId"
Write-Host "`nAny user with Global Reader (or higher) can now run, e.g.:"
Write-Host "  Test-EntraPostureAccess -TenantId '$TenantId' -ClientId '$clientId' -AuthMode Delegated"
