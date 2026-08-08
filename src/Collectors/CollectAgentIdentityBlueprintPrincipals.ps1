#Requires -Version 7.4

function Get-EntraPostureAgentIdentityBlueprintPrincipalCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAgentIdentityBlueprintPrincipalCollector's permission/
        coverage requirements.

        .DESCRIPTION
        AgentIdentityBlueprintPrincipal.Read.All is Microsoft's documented least-privileged
        permission (confirmed directly against the live "List agentIdentityBlueprintPrincipal
        objects" Graph reference page, re-fetched 2026-08-07). Feeds every "foreign" AGT-*
        finding (AGT-004/005/008/009/011/012/017) via its own appOwnerOrganizationId field --
        VNext build order item 13.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AgentIdentityBlueprintPrincipals' `
        -RequiredPermissions @('AgentIdentityBlueprintPrincipal.Read.All') `
        -EndpointsUsed @('/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal') `
        -AffectedControlIds @('AGT-004', 'AGT-005', 'AGT-008', 'AGT-009', 'AGT-011', 'AGT-012', 'AGT-017') `
        -AffectedReportSections @('Agent Identities')
}

function Invoke-EntraPostureAgentIdentityBlueprintPrincipalCollector {
    <#
        .SYNOPSIS
        Collects agent identity blueprint principals, normalized to canonical Entity records.
        Read-only: one allowlisted, paginated Graph GET call.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (AgentIdentityBlueprintPrincipal[]).
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

    $path = '/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal'
    $rawPrincipals = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawPrincipal in $rawPrincipals) {
        ConvertTo-EntraPostureAgentIdentityBlueprintPrincipalEntity -RawBlueprintPrincipal $rawPrincipal -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
