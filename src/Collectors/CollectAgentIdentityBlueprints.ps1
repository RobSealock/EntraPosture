#Requires -Version 7.4

function Get-EntraPostureAgentIdentityBlueprintCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAgentIdentityBlueprintCollector's permission/coverage
        requirements.

        .DESCRIPTION
        AgentIdentityBlueprint.Read.All is Microsoft's documented least-privileged permission for
        listing blueprints (confirmed directly against the live "List agentIdentityBlueprint
        objects" Graph reference page, re-fetched 2026-08-07); owners are listed via the ordinary
        application-owners endpoint, governed by the already-widely-held Application.Read.All
        (confirmed against the live "List owners of an application" reference page, same date) --
        no separate agent-specific owners permission exists. Feeds AGT-001 (blueprint client
        secrets) and AGT-017 (blueprint owner tier), VNext build order item 13.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AgentIdentityBlueprints' `
        -RequiredPermissions @('AgentIdentityBlueprint.Read.All', 'Application.Read.All') `
        -EndpointsUsed @(
            '/v1.0/applications/microsoft.graph.agentIdentityBlueprint',
            '/v1.0/applications/{applicationId}/owners'
        ) `
        -AffectedControlIds @('AGT-001', 'AGT-017') `
        -AffectedReportSections @('Agent Identities')
}

function Invoke-EntraPostureAgentIdentityBlueprintOwnerFetch {
    <#
        .SYNOPSIS
        Fetches and normalizes one blueprint's owners -- the per-blueprint unit of work
        Invoke-EntraPostureAgentIdentityBlueprintCollector's N+1 fetch dispatches concurrently
        via Invoke-EntraPostureBoundedParallel, the same pattern
        Invoke-EntraPostureGroupTransitiveMemberFetch established (VNext build order item 6).

        .PARAMETER BlueprintEntityId
        .PARAMETER AccessToken
        .PARAMETER CollectorVersion
        .PARAMETER CollectedAt
        .PARAMETER RequestHostOverride
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride

        .OUTPUTS
        Ordered dictionary: Relationships (OwnerOf[]).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$BlueprintEntityId,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$CollectedAt,

        [Parameter(Mandatory)]
        [string]$RequestHostOverride,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https'
    )

    $sendParams = @{
        RequestHost  = $RequestHostOverride
        ApiStability = 'Stable'
        AccessToken  = $AccessToken
    }
    if ($AllowlistOverride) { $sendParams['AllowlistOverride'] = $AllowlistOverride }
    if ($SchemeOverride -ne 'https') { $sendParams['SchemeOverride'] = $SchemeOverride }

    $ownersPath = "/v1.0/applications/$BlueprintEntityId/owners"
    $rawOwners = Send-EntraPostureRequest @sendParams -Path $ownersPath -Method GET

    $relationships = foreach ($rawOwner in $rawOwners) {
        ConvertTo-EntraPostureOwnerOfRelationship -RawOwner $rawOwner -OwnedEntityId $BlueprintEntityId `
            -CollectorVersion $CollectorVersion -SourceEndpoint $ownersPath -CollectedAt $CollectedAt
    }

    return [ordered]@{
        Relationships = @($relationships)
    }
}

function Invoke-EntraPostureAgentIdentityBlueprintCollector {
    <#
        .SYNOPSIS
        Collects agent identity blueprints and (VNext build order item 13) each blueprint's
        owners, normalized to canonical Entity and Relationship records. Read-only: one
        paginated Graph GET call listing blueprints, plus a bounded-concurrent owners fetch per
        blueprint.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.
        .PARAMETER OwnerFetchConcurrency
        Bounded concurrency for the per-blueprint owners fetch (default four, matching every
        other N+1 collector in this project).

        .OUTPUTS
        Ordered dictionary: Entities (AgentIdentityBlueprint[]), Relationships (OwnerOf[]).
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
        [string]$RequestHostOverride = 'graph.microsoft.com',

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$OwnerFetchConcurrency = 4
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

    $path = '/v1.0/applications/microsoft.graph.agentIdentityBlueprint'
    $rawBlueprints = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $blueprintEntities = @(foreach ($rawBlueprint in $rawBlueprints) {
        ConvertTo-EntraPostureAgentIdentityBlueprintEntity -RawBlueprint $rawBlueprint -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    })

    $ownerFetchParameterSets = @(foreach ($blueprintEntity in $blueprintEntities) {
        $parameterSet = @{
            BlueprintEntityId   = $blueprintEntity.entityId
            AccessToken         = $AccessToken
            CollectorVersion    = $collectorVersion
            CollectedAt         = $collectedAt
            RequestHostOverride = $RequestHostOverride
        }
        if ($AllowlistOverride) { $parameterSet['AllowlistOverride'] = $AllowlistOverride }
        if ($SchemeOverride -ne 'https') { $parameterSet['SchemeOverride'] = $SchemeOverride }
        $parameterSet
    })

    $ownerFetchResults = Invoke-EntraPostureBoundedParallel -CommandName 'Invoke-EntraPostureAgentIdentityBlueprintOwnerFetch' `
        -ParameterSets $ownerFetchParameterSets -ThrottleLimit $OwnerFetchConcurrency

    $ownerRelationships = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $ownerFetchResults.Count; $i++) {
        $fetchResult = $ownerFetchResults[$i]
        if (-not $fetchResult.Success) {
            throw "Invoke-EntraPostureAgentIdentityBlueprintCollector: fetching owners for blueprint '$($blueprintEntities[$i].entityId)' failed: $($fetchResult.ErrorMessage)"
        }
        foreach ($r in @($fetchResult.Result.Relationships)) { $ownerRelationships.Add($r) }
    }

    return [ordered]@{
        Entities      = @($blueprintEntities)
        Relationships = @($ownerRelationships.ToArray())
    }
}
