#Requires -Version 7.4

function Get-EntraPostureServicePrincipalCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureServicePrincipalCollector's permission/coverage
        requirements.

        .DESCRIPTION
        Application.Read.All (same permission family as Applications -- service principals are
        the same underlying Graph resource family) is Microsoft's documented least-privileged
        permission. No control depends on ServicePrincipal/ManagedIdentity evidence yet.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'ServicePrincipals' `
        -RequiredPermissions @('Application.Read.All') `
        -EndpointsUsed @('/v1.0/servicePrincipals') `
        -AffectedControlIds @('MAI-002', 'MAI-003') `
        -AffectedReportSections @('Applications')
}

function Invoke-EntraPostureServicePrincipalCollector {
    <#
        .SYNOPSIS
        Collects service principals (enterprise apps and managed identities together),
        normalized to canonical Entity records -- entityType 'ServicePrincipal' or
        'ManagedIdentity' depending on each record's own servicePrincipalType (see the
        normalizer's own DESCRIPTION). Read-only: one allowlisted, paginated Graph GET call.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (ServicePrincipal[] and/or ManagedIdentity[], mixed).
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

    $path = '/v1.0/servicePrincipals'
    $rawServicePrincipals = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawServicePrincipal in $rawServicePrincipals) {
        ConvertTo-EntraPostureServicePrincipalEntity -RawServicePrincipal $rawServicePrincipal -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
