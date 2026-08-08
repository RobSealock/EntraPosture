#Requires -Version 7.4

function Get-EntraPostureUserSignInActivityCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureUserSignInActivityCollector's permission/coverage
        requirements.

        .DESCRIPTION
        AuditLog.Read.All is Microsoft's documented permission for the signInActivity property
        (confirmed live 2026-08-08 -- see NormalizeUserSignInActivity.ps1's own DESCRIPTION for
        the full citation, including the P1/P2 licensing dependency this permission alone does
        not satisfy). Deliberately its own collector, not folded into CollectUsers.ps1, so an
        unlicensed tenant's failure here is isolated to USR-005 alone. New collector, VNext
        build order item 2's new-evidence phase (batch 8, 2026-08-08).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'UserSignInActivity' `
        -RequiredPermissions @('AuditLog.Read.All') `
        -EndpointsUsed @('/v1.0/users') `
        -AffectedControlIds @('USR-005') `
        -AffectedReportSections @('Identity')
}

function Invoke-EntraPostureUserSignInActivityCollector {
    <#
        .SYNOPSIS
        Collects every user's signInActivity, normalized to canonical UserSignInActivity Entity
        records. Read-only: one allowlisted, paginated Graph GET call against the same
        /v1.0/users path CollectUsers.ps1 already uses, with a distinct $select -- Microsoft
        Graph automatically caps the page size to 500 (rather than the ordinary 999) whenever
        signInActivity is selected or filtered on, a limit this project's existing
        follow-@odata.nextLink pagination in Send-EntraPostureRequest already handles
        transparently, needing no special-case code here.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (UserSignInActivity[]).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https',

        [Parameter()]
        [string]$RequestHostOverride = 'graph.microsoft.com'
    )

    $collectorVersion = (Get-EntraPostureToolVersionInfo).ToolVersion
    $collectedAt = (Get-Date).ToUniversalTime().ToString('o')

    $sendParams = @{
        RequestHost  = $RequestHostOverride
        ApiStability = 'Stable'
        AccessToken  = $AccessToken
    }
    if ($AllowlistOverride) { $sendParams['AllowlistOverride'] = $AllowlistOverride }
    if ($SchemeOverride -ne 'https') { $sendParams['SchemeOverride'] = $SchemeOverride }

    $path = '/v1.0/users'
    $queryParams = @{ '$select' = 'id,signInActivity' }
    $rawUsers = Send-EntraPostureRequest @sendParams -Path $path -Method GET -QueryParameters $queryParams

    $entities = foreach ($rawUser in $rawUsers) {
        ConvertTo-EntraPostureUserSignInActivityEntity -RawUser $rawUser -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
