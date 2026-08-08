#Requires -Version 7.4

function Get-EntraPostureAgentIdentityCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAgentIdentityCollector's permission/coverage requirements.

        .DESCRIPTION
        AgentIdentity.Read.All is Microsoft's documented least-privileged permission (confirmed
        directly against the live "List agentIdentity objects" Graph reference page, re-fetched
        2026-08-07). Feeds AGT-004/005/008/009 (correlated against existing DirectoryRoleAssignment/
        AzureRoleAssignment evidence) -- VNext build order item 13.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AgentIdentities' `
        -RequiredPermissions @('AgentIdentity.Read.All') `
        -EndpointsUsed @('/v1.0/servicePrincipals/microsoft.graph.agentIdentity') `
        -AffectedControlIds @('AGT-004', 'AGT-005', 'AGT-008', 'AGT-009') `
        -AffectedReportSections @('Agent Identities')
}

function Invoke-EntraPostureAgentIdentityCollector {
    <#
        .SYNOPSIS
        Collects agent identities, normalized to canonical Entity records. Read-only: one
        allowlisted, paginated Graph GET call.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (AgentIdentity[]).
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

    $path = '/v1.0/servicePrincipals/microsoft.graph.agentIdentity'
    $rawAgentIdentities = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawAgentIdentity in $rawAgentIdentities) {
        ConvertTo-EntraPostureAgentIdentityEntity -RawAgentIdentity $rawAgentIdentity -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
