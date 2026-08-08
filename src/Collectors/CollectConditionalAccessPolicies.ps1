#Requires -Version 7.4

function Get-EntraPostureConditionalAccessPolicyCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureConditionalAccessPolicyCollector's permission/coverage
        requirements (input to Test-EntraPosturePreflight).

        .DESCRIPTION
        Policy.Read.All is Microsoft's documented least-privileged permission for reading
        Conditional Access policies. Phase 5 collected only a minimal field set to prove the
        pattern extends to this domain; Phase 8 expanded the normalizer to the full condition/
        grant-control/session-control object graph the CA simulation engine needs, and wired
        'CA-001' (Global Administrator MFA coverage) as the first control consuming it.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'ConditionalAccessPolicies' `
        -RequiredPermissions @('Policy.Read.All') `
        -EndpointsUsed @('/v1.0/identity/conditionalAccess/policies') `
        -AffectedControlIds @('CA-001', 'CA-002') `
        -AffectedReportSections @('Conditional Access')
}

function Invoke-EntraPostureConditionalAccessPolicyCollector {
    <#
        .SYNOPSIS
        Collects Conditional Access policies, normalized to canonical Entity records (minimal
        field set -- see the normalizer's own DESCRIPTION for why full condition/grant-control
        fidelity is out of scope here). Read-only: one allowlisted Graph GET call.

        .PARAMETER AccessToken
        A Graph-audience access token.

        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        Test-only passthrough to Send-EntraPostureRequest.

        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (ConditionalAccessPolicy[]).
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

    $path = '/v1.0/identity/conditionalAccess/policies'
    $rawPolicies = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawPolicy in $rawPolicies) {
        ConvertTo-EntraPostureConditionalAccessPolicyEntity -RawPolicy $rawPolicy -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
