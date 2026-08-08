#Requires -Version 7.4

function Get-EntraPostureUserCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureUserCollector's permission/coverage requirements.

        .DESCRIPTION
        User.Read.All is Microsoft's documented least-privileged permission for listing users.
        AffectedControlIds was empty through 2026-08-07 -- PIM/role-assignment relationships
        (Phase 5's PRIV-001, Phase 6's PimEligible) reference user entityIds without requiring
        the User entity itself to be independently collected. USR-007/008 (2026-08-08, VNext
        build order item 2 batch 4) are the first controls to read the User entity's own
        properties directly (onPremisesSyncEnabled).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'Users' `
        -RequiredPermissions @('User.Read.All') `
        -EndpointsUsed @('/v1.0/users') `
        -AffectedControlIds @('USR-007', 'USR-008') `
        -AffectedReportSections @('Identity')
}

function Invoke-EntraPostureUserCollector {
    <#
        .SYNOPSIS
        Collects users, normalized to canonical Entity records. Read-only: one allowlisted,
        paginated Graph GET call.

        .PARAMETER AccessToken
        A Graph-audience access token.

        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (User[]).
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

    # $select required -- accountEnabled/userType/onPremisesSyncEnabled are not in Microsoft's
    # documented default property set for this endpoint (confirmed live 2026-08-08; see
    # NormalizeUser.ps1's own DESCRIPTION for the citation and the pre-existing bug this fixes).
    $path = '/v1.0/users'
    $queryParams = @{ '$select' = 'id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled' }
    $rawUsers = Send-EntraPostureRequest @sendParams -Path $path -Method GET -QueryParameters $queryParams

    $entities = foreach ($rawUser in $rawUsers) {
        ConvertTo-EntraPostureUserEntity -RawUser $rawUser -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
