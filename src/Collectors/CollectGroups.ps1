#Requires -Version 7.4

function Get-EntraPostureGroupCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureGroupCollector's permission/coverage requirements.

        .DESCRIPTION
        Group.Read.All and GroupMember.Read.All are Microsoft's documented least-privileged
        permissions for listing groups and their transitive membership respectively. Feeds
        'GRP-005' (Phase 7, role-assignable group transitive-membership size check).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'Groups' `
        -RequiredPermissions @('Group.Read.All', 'GroupMember.Read.All') `
        -EndpointsUsed @('/v1.0/groups', '/v1.0/groups/{groupId}/transitiveMembers') `
        -AffectedControlIds @('GRP-005', 'GRP-003', 'GRP-004', 'USR-006') `
        -AffectedReportSections @('Identity')
}

function Invoke-EntraPostureGroupTransitiveMemberFetch {
    <#
        .SYNOPSIS
        Fetches and normalizes one group's transitiveMembers -- the per-group unit of work
        Invoke-EntraPostureGroupCollector's N+1 fetch pattern dispatches concurrently via
        Invoke-EntraPostureBoundedParallel (VNext build order item 6, "bounded collection
        concurrency," specifically named in that item's own VNext.md text: "including Groups'
        real N+1 fetch pattern").

        .DESCRIPTION
        Extracted into its own standalone function for the same reason
        GraphCollectorDispatch.ps1's Invoke-EntraPostureGraphCollectorDispatch was: a bounded
        runspace pool invokes a named, already-loaded function per unit of work, not an inline
        loop body. Side-effect-free with respect to anything outside its own parameters/return
        value, matching Invoke-EntraPostureBoundedParallel's own requirement for any
        -CommandName target.

        .PARAMETER GroupEntityId
        .PARAMETER AccessToken
        .PARAMETER CollectorVersion
        .PARAMETER CollectedAt
        .PARAMETER RequestHostOverride
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride

        .OUTPUTS
        Ordered dictionary: Relationships (TransitiveMemberOf[]).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$GroupEntityId,

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

    $membersPath = "/v1.0/groups/$GroupEntityId/transitiveMembers"
    $rawMembers = Send-EntraPostureRequest @sendParams -Path $membersPath -Method GET

    $relationships = foreach ($rawMember in $rawMembers) {
        ConvertTo-EntraPostureGroupTransitiveMembershipRelationship -RawMember $rawMember `
            -GroupEntityId $GroupEntityId -CollectorVersion $CollectorVersion -SourceEndpoint $membersPath -CollectedAt $CollectedAt
    }

    return [ordered]@{
        Relationships = @($relationships)
    }
}

function Invoke-EntraPostureGroupCollector {
    <#
        .SYNOPSIS
        Collects every group and its transitive membership, normalized to canonical
        Entity/Relationship records. Read-only: one paginated Graph GET call per group (now
        bounded-concurrent, VNext build order item 6) plus one paginated call listing groups.

        .DESCRIPTION
        Phase 1 finding (carried into the Phase 4 allowlist's own inline comment on this exact
        path): transitiveMembers, not direct members, matches EntraFalcon/Conditional Access
        Validator precedent and this project's own 'TransitiveMemberOf' relationship type. The
        N+1 fetch pattern here (one call per group) mirrors
        Invoke-EntraPostureDirectoryRoleCollector's existing per-role-members pattern.
        Bounded collection concurrency (section 12's "default four") is applied via
        Invoke-EntraPostureBoundedParallel -- results merge back in the same order $rawGroups
        was returned in, regardless of which group's transitiveMembers call actually finished
        first (the same determinism guarantee CollectAndSeal.ps1's own top-level collector
        concurrency relies on).

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (Group[]), Relationships (TransitiveMemberOf[]).
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
        [int]$MemberFetchConcurrency = 4
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

    $rawGroups = Send-EntraPostureRequest @sendParams -Path '/v1.0/groups' -Method GET

    $entities = @(foreach ($rawGroup in $rawGroups) {
        ConvertTo-EntraPostureGroupEntity -RawGroup $rawGroup -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint '/v1.0/groups' -CollectedAt $collectedAt
    })

    $memberFetchParameterSets = @(foreach ($groupEntity in $entities) {
        $parameterSet = @{
            GroupEntityId       = $groupEntity.entityId
            AccessToken         = $AccessToken
            CollectorVersion    = $collectorVersion
            CollectedAt         = $collectedAt
            RequestHostOverride = $RequestHostOverride
        }
        if ($AllowlistOverride) { $parameterSet['AllowlistOverride'] = $AllowlistOverride }
        if ($SchemeOverride -ne 'https') { $parameterSet['SchemeOverride'] = $SchemeOverride }
        $parameterSet
    })

    $memberFetchResults = Invoke-EntraPostureBoundedParallel -CommandName 'Invoke-EntraPostureGroupTransitiveMemberFetch' `
        -ParameterSets $memberFetchParameterSets -ThrottleLimit $MemberFetchConcurrency

    $relationships = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $memberFetchResults.Count; $i++) {
        $fetchResult = $memberFetchResults[$i]
        if (-not $fetchResult.Success) {
            throw "Invoke-EntraPostureGroupCollector: fetching transitiveMembers for group '$($entities[$i].entityId)' failed: $($fetchResult.ErrorMessage)"
        }
        foreach ($r in @($fetchResult.Result.Relationships)) { $relationships.Add($r) }
    }

    return [ordered]@{
        Entities      = @($entities)
        Relationships = @($relationships.ToArray())
    }
}
