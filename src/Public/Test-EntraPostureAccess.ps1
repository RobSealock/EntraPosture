#Requires -Version 7.4

function Test-EntraPostureAccess {
    <#
        .SYNOPSIS
        Checks authentication, permissions, and report-section coverage without collecting
        evidence.

        .DESCRIPTION
        Preflight-only command (engineering plan section 6.2/7.2). Authenticates (real
        Connect-EntraPostureDelegated/Connect-EntraPostureCertificate, unless
        -AccessTokenOverride is supplied for testing), then projects the Graph token's granted
        permissions against every declared collector requirement via
        Test-EntraPosturePreflight -- without ever calling a collector endpoint, so
        accessVerified is always false and evidenceStatus is never 'Collected' here (section
        7.2 item 4: "access actually verified through endpoint responses" only ever happens
        during real collection, which this command deliberately never performs).

        .PARAMETER TenantId
        .PARAMETER ClientId
        .PARAMETER AuthMode
        .PARAMETER Certificate
        Required when -AuthMode is 'Certificate'.

        .PARAMETER Browser
        .PARAMETER PrivateBrowsing
        Optional, only meaningful when -AuthMode is 'Delegated'. See
        Connect-EntraPostureDelegated's parameters of the same names.

        .PARAMETER AccessTokenOverride
        Test-only. See New-EntraPostureSnapshot's parameter of the same name.

        .OUTPUTS
        Ordered dictionary matching coverage.schema.json (accessVerified always false, since no
        endpoint was ever called).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [ValidateSet('Delegated', 'Certificate')]
        [string]$AuthMode,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [ValidateSet('Edge', 'Chrome', 'Firefox')]
        [string]$Browser,

        [Parameter()]
        [switch]$PrivateBrowsing,

        [Parameter()]
        [string]$AccessTokenOverride
    )

    if (-not $AccessTokenOverride -and $AuthMode -eq 'Certificate' -and -not $Certificate) {
        throw 'Test-EntraPostureAccess: -Certificate is required when -AuthMode is Certificate (unless -AccessTokenOverride bypasses authentication entirely).'
    }

    if ($AccessTokenOverride) {
        $graphToken = $AccessTokenOverride
    } else {
        $tokenCache = New-EntraPostureTokenCache
        $graphScope = 'https://graph.microsoft.com/.default'
        if ($AuthMode -eq 'Delegated') {
            $graphResult = Connect-EntraPostureDelegated -ClientId $ClientId -TenantId $TenantId -Scope $graphScope -TokenCache $tokenCache -Browser $Browser -PrivateBrowsing:$PrivateBrowsing
        } else {
            $graphResult = Connect-EntraPostureCertificate -ClientId $ClientId -TenantId $TenantId -Certificate $Certificate -Scope $graphScope -TokenCache $tokenCache
        }
        $graphToken = $graphResult.AccessToken
    }

    $graphGranted = (Get-EntraPostureTokenGrantedPermission -Jwt $graphToken).Permissions

    $allRequirements = Get-EntraPostureAllCollectorRequirement
    $armCollectorNames = @('AzureRoleAssignments', 'AzureSubscriptions', 'AzureManagementGroups', 'AzureRoleDefinitions')
    $graphRequirements = @($allRequirements | Where-Object { $_.CollectorName -notin $armCollectorNames })
    $armRequirements = @($allRequirements | Where-Object { $_.CollectorName -in $armCollectorNames })

    $graphCoverage = Test-EntraPosturePreflight -CollectorRequirements $graphRequirements -GrantedPermissions $graphGranted
    $armCoverage = Test-EntraPosturePreflight -CollectorRequirements $armRequirements -GrantedPermissions @()

    return [ordered]@{
        collectors = @(@($graphCoverage.collectors) + @($armCoverage.collectors))
    }
}
