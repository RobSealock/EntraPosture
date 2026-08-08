#Requires -Version 7.4

function Get-EntraPostureCrossTenantAccessPolicyPartnerCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureCrossTenantAccessPolicyPartnerCollector's permission/
        coverage requirements.

        .DESCRIPTION
        Policy.Read.All, same permission and same confirmation basis as Phase 5's
        CrossTenantAccessPolicy collector requirement (00-permission-report-matrix.md: "List
        partners" confirmed 2026-08-06). Feeds the future XTA-002 control (Phase 7).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'CrossTenantAccessPolicyPartners' `
        -RequiredPermissions @('Policy.Read.All') `
        -EndpointsUsed @('/v1.0/policies/crossTenantAccessPolicy/partners') `
        -AffectedControlIds @('XTA-002') `
        -AffectedReportSections @('Cross-Tenant Access')
}

function Invoke-EntraPostureCrossTenantAccessPolicyPartnerCollector {
    <#
        .SYNOPSIS
        Collects cross-tenant access partner-specific overrides, normalized to canonical Entity
        records. Read-only: one allowlisted, paginated Graph GET call.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (CrossTenantAccessPolicyPartner[]).
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

    $path = '/v1.0/policies/crossTenantAccessPolicy/partners'
    $rawPartners = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawPartner in $rawPartners) {
        ConvertTo-EntraPostureCrossTenantAccessPolicyPartnerEntity -RawPartner $rawPartner -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
