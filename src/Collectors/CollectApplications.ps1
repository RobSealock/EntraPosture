#Requires -Version 7.4

function Get-EntraPostureApplicationCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureApplicationCollector's permission/coverage requirements.

        .DESCRIPTION
        Application.Read.All is Microsoft's documented least-privileged permission for listing
        app registrations, and already covers the /applications/{id}/owners endpoint too
        (confirmed live against the "List owners of an application" Graph reference page --
        no separate scope needed). APP-003 (added 2026-08-08, VNext build order item 2 batch 6,
        the new-evidence phase) is the first control to need this collector's owners N+1 fetch.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'Applications' `
        -RequiredPermissions @('Application.Read.All') `
        -EndpointsUsed @('/v1.0/applications', '/v1.0/applications/{applicationId}/owners') `
        -AffectedControlIds @('APP-001', 'APP-002', 'APP-003') `
        -AffectedReportSections @('Applications')
}

function Invoke-EntraPostureApplicationOwnerFetch {
    <#
        .SYNOPSIS
        Fetches and normalizes one application's owners -- the per-application unit of work
        Invoke-EntraPostureApplicationCollector's N+1 fetch dispatches concurrently via
        Invoke-EntraPostureBoundedParallel, the same pattern
        Invoke-EntraPostureAgentIdentityBlueprintOwnerFetch already established for the
        identical endpoint shape (an agentIdentityBlueprint IS an application, per
        ConvertTo-EntraPostureAgentIdentityBlueprintEntity's own DESCRIPTION -- this is the same
        owners endpoint, generalized to every ordinary Application entity too, not a new
        pattern).

        .PARAMETER ApplicationEntityId
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
        [string]$ApplicationEntityId,

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

    $ownersPath = "/v1.0/applications/$ApplicationEntityId/owners"
    $rawOwners = Send-EntraPostureRequest @sendParams -Path $ownersPath -Method GET

    $relationships = foreach ($rawOwner in $rawOwners) {
        ConvertTo-EntraPostureOwnerOfRelationship -RawOwner $rawOwner -OwnedEntityId $ApplicationEntityId `
            -CollectorVersion $CollectorVersion -SourceEndpoint $ownersPath -CollectedAt $CollectedAt
    }

    return [ordered]@{
        Relationships = @($relationships)
    }
}

function Invoke-EntraPostureApplicationCollector {
    <#
        .SYNOPSIS
        Collects app registrations and (VNext build order item 2 batch 6, APP-003) each
        application's owners, normalized to canonical Entity and Relationship records.
        Read-only: one paginated Graph GET call, plus a bounded-concurrent owners fetch per
        application.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.
        .PARAMETER OwnerFetchConcurrency
        Bounded concurrency for the per-application owners fetch (default four, matching every
        other N+1 collector in this project).

        .OUTPUTS
        Ordered dictionary: Entities (Application[]), Relationships (OwnerOf[]).
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

    $path = '/v1.0/applications'
    $rawApplications = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = @(foreach ($rawApplication in $rawApplications) {
        ConvertTo-EntraPostureApplicationEntity -RawApplication $rawApplication -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    })

    $ownerFetchParameterSets = @(foreach ($applicationEntity in $entities) {
        $parameterSet = @{
            ApplicationEntityId = $applicationEntity.entityId
            AccessToken         = $AccessToken
            CollectorVersion    = $collectorVersion
            CollectedAt         = $collectedAt
            RequestHostOverride = $RequestHostOverride
        }
        if ($AllowlistOverride) { $parameterSet['AllowlistOverride'] = $AllowlistOverride }
        if ($SchemeOverride -ne 'https') { $parameterSet['SchemeOverride'] = $SchemeOverride }
        $parameterSet
    })

    $ownerFetchResults = Invoke-EntraPostureBoundedParallel -CommandName 'Invoke-EntraPostureApplicationOwnerFetch' `
        -ParameterSets $ownerFetchParameterSets -ThrottleLimit $OwnerFetchConcurrency

    $ownerRelationships = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $ownerFetchResults.Count; $i++) {
        $fetchResult = $ownerFetchResults[$i]
        if (-not $fetchResult.Success) {
            throw "Invoke-EntraPostureApplicationCollector: fetching owners for application '$($entities[$i].entityId)' failed: $($fetchResult.ErrorMessage)"
        }
        foreach ($r in @($fetchResult.Result.Relationships)) { $ownerRelationships.Add($r) }
    }

    return [ordered]@{
        Entities      = @($entities)
        Relationships = @($ownerRelationships.ToArray())
    }
}
