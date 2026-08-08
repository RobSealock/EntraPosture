#Requires -Version 7.4

function Get-EntraPostureCrossTenantAccessPolicyCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureCrossTenantAccessPolicyCollector's permission/coverage
        requirements (input to Test-EntraPosturePreflight).

        .DESCRIPTION
        Policy.Read.All is Microsoft's documented least-privileged permission for reading the
        default cross-tenant access policy. Feeds the 'XTA-001' predicate control and the
        'Cross-Tenant Access' report section. Also feeds 'XTA-002' (Phase 7) -- that control
        compares each CrossTenantAccessPolicyPartner override against this same default policy,
        so this collector's success is one of two coverage requirements XTA-002's evaluation
        gate needs (the other being CrossTenantAccessPolicyPartners).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'CrossTenantAccessPolicy' `
        -RequiredPermissions @('Policy.Read.All') `
        -EndpointsUsed @('/v1.0/policies/crossTenantAccessPolicy') `
        -AffectedControlIds @('XTA-001', 'XTA-002') `
        -AffectedReportSections @('Cross-Tenant Access')
}

function Invoke-EntraPostureCrossTenantAccessPolicyCollector {
    <#
        .SYNOPSIS
        Collects the tenant's default cross-tenant access policy, normalized to a single
        canonical Entity record. Read-only: one allowlisted Graph GET call against a singleton
        resource (no pagination -- there is exactly one default policy per tenant).

        .PARAMETER AccessToken
        A Graph-audience access token.

        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        Test-only passthrough to Send-EntraPostureRequest.

        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (CrossTenantAccessPolicy[], always exactly one element).
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
        RequestHost = $RequestHostOverride
        ApiStability = 'Stable'
        AccessToken  = $AccessToken
    }
    if ($AllowlistOverride) { $sendParams['AllowlistOverride'] = $AllowlistOverride }
    if ($SchemeOverride -ne 'https') { $sendParams['SchemeOverride'] = $SchemeOverride }

    $path = '/v1.0/policies/crossTenantAccessPolicy'
    # This endpoint returns a single JSON object, not a paginated { value: [...] } envelope --
    # Send-EntraPostureRequest still returns a 1-element array (the whole object as its only
    # element), consistent with how it treats any non-paginated response body.
    $rawPolicies = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawPolicy in $rawPolicies) {
        ConvertTo-EntraPostureCrossTenantAccessPolicyEntity -RawPolicy $rawPolicy -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
