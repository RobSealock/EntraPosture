#Requires -Version 7.4

function Get-EntraPostureNamedLocationCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureNamedLocationCollector's permission/coverage
        requirements.

        .DESCRIPTION
        Policy.Read.All, confirmed directly against Microsoft Graph's "List namedLocations"
        documentation (least-privileged delegated/application permission for
        GET /identity/conditionalAccess/namedLocations, re-fetched 2026-08-07) -- already a
        required scope for this project's other collectors (ConditionalAccessPolicies,
        TenantPolicies), so no new permission grant is needed. No control currently depends on
        this evidence directly (AffectedControlIds empty, not an oversight) -- it feeds the
        Conditional Access simulation engine's named-location resolution
        (VNext build order item 4), not a control evaluator.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'NamedLocations' `
        -RequiredPermissions @('Policy.Read.All') `
        -EndpointsUsed @('/v1.0/identity/conditionalAccess/namedLocations') `
        -AffectedControlIds @() `
        -AffectedReportSections @('Conditional Access')
}

function Invoke-EntraPostureNamedLocationCollector {
    <#
        .SYNOPSIS
        Collects every named location (IP-range and country/region), normalized to canonical
        Entity records. Read-only: one allowlisted, paginated Graph GET call.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (NamedLocation[]).
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

    $path = '/v1.0/identity/conditionalAccess/namedLocations'
    $rawLocations = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawLocation in $rawLocations) {
        ConvertTo-EntraPostureNamedLocationEntity -RawLocation $rawLocation -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
