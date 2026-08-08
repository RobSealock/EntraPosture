#Requires -Version 7.4

function Get-EntraPosturePimForGroupsCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPosturePimForGroupsCollector's permission/coverage requirements.

        .DESCRIPTION
        PrivilegedEligibilitySchedule.Read.AzureADGroup and
        PrivilegedAssignmentSchedule.Read.AzureADGroup are Microsoft's documented
        least-privileged permissions (confirmed directly against the live "List
        eligibilityScheduleInstances"/"List assignmentScheduleInstances" Graph reference pages,
        re-fetched 2026-08-07) -- neither is held by any existing collector in this project (a
        genuinely new permission family, not an extension of PimEligibility's
        RoleManagement.Read.Directory, which only covers directory-role PIM). Both endpoints
        **require** a $filter scoped to a groupId or principalId -- there is no unfiltered
        tenant-wide list -- so this collector must first enumerate every role-assignable group
        (via the same '/v1.0/groups' endpoint the Groups collector already uses, called again
        here independently rather than depending on that collector's own output, matching this
        project's "every collector is self-contained and independently dispatchable" discipline)
        and then issue two filtered calls per group. Feeds PIMG-001/002, VNext build order item
        13.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'PimForGroups' `
        -RequiredPermissions @('Group.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'PrivilegedAssignmentSchedule.Read.AzureADGroup') `
        -EndpointsUsed @(
            '/v1.0/groups',
            '/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances',
            '/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances'
        ) `
        -AffectedControlIds @('PIMG-001', 'PIMG-002') `
        -AffectedReportSections @('PIM')
}

function Invoke-EntraPosturePimForGroupsScheduleFetch {
    <#
        .SYNOPSIS
        Fetches one role-assignable group's PIM-for-Groups eligibility and active-assignment
        schedule instances -- the per-group unit of work
        Invoke-EntraPosturePimForGroupsCollector's N+1 fetch dispatches concurrently via
        Invoke-EntraPostureBoundedParallel.

        .DESCRIPTION
        Two sequential Graph calls per group (eligibility, then active assignments) -- the same
        "one unit of work covers everything needed for this driver item" shape
        Invoke-EntraPostureAccessReviewInstanceFetch already established for a two-call-per-item
        N+1. Both calls use -QueryParameters (never string-concatenated into -Path) so the
        endpoint allowlist match is against the bare path template, exactly as every other
        filtered call in this project already does.

        .PARAMETER GroupEntityId
        .PARAMETER AccessToken
        .PARAMETER CollectorVersion
        .PARAMETER CollectedAt
        .PARAMETER RequestHostOverride
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride

        .OUTPUTS
        Ordered dictionary: Relationships (PimEligible[] + PimActive[]).
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

    $filterParams = @{ '$filter' = "groupId eq '$GroupEntityId'" }

    $eligibilityPath = '/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances'
    $rawEligibility = Send-EntraPostureRequest @sendParams -Path $eligibilityPath -Method GET -QueryParameters $filterParams

    $activePath = '/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances'
    $rawActive = Send-EntraPostureRequest @sendParams -Path $activePath -Method GET -QueryParameters $filterParams

    $eligibilityRelationships = foreach ($rawInstance in $rawEligibility) {
        ConvertTo-EntraPosturePimGroupEligibilityRelationship -RawInstance $rawInstance -GroupEntityId $GroupEntityId `
            -CollectorVersion $CollectorVersion -SourceEndpoint $eligibilityPath -CollectedAt $CollectedAt
    }
    $activeRelationships = foreach ($rawInstance in $rawActive) {
        ConvertTo-EntraPosturePimGroupActiveRelationship -RawInstance $rawInstance -GroupEntityId $GroupEntityId `
            -CollectorVersion $CollectorVersion -SourceEndpoint $activePath -CollectedAt $CollectedAt
    }

    return [ordered]@{
        Relationships = @(@($eligibilityRelationships) + @($activeRelationships))
    }
}

function Invoke-EntraPosturePimForGroupsCollector {
    <#
        .SYNOPSIS
        Collects PIM-for-Groups eligibility and active-assignment schedule instances for every
        role-assignable group, normalized to canonical Relationship records. Read-only: one
        paginated Graph GET call listing groups, plus a bounded-concurrent pair of filtered
        calls per role-assignable group.

        .DESCRIPTION
        Scoped to isAssignableToRole=true groups only, matching PIMG-001/002's own applicability
        (see those controls' own definitions) -- an unbounded per-group N+1 over every group in
        the tenant would be both wasteful and outside what either control actually evaluates.

        Takes no -TenantScope, the same omission Invoke-EntraPosturePimEligibilityCollector
        already established -- relationships carry no tenantScope field of their own, and this
        project's convention (confirmed by that earlier collector's own dispatch case) is to
        drop a parameter a collector genuinely has no use for, not carry it for uniformity with
        collectors that do need it.

        .PARAMETER AccessToken
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.
        .PARAMETER ScheduleFetchConcurrency
        Bounded concurrency for the per-group schedule fetch (default four).

        .OUTPUTS
        Ordered dictionary: Relationships (PimEligible[] + PimActive[], group-targeted only).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https',

        [Parameter()]
        [string]$RequestHostOverride = 'graph.microsoft.com',

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$ScheduleFetchConcurrency = 4
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

    $groupsPath = '/v1.0/groups'
    $rawGroups = Send-EntraPostureRequest @sendParams -Path $groupsPath -Method GET

    $roleAssignableGroupIds = @($rawGroups | Where-Object { [bool]$_['isAssignableToRole'] } | ForEach-Object { [string]$_['id'] })

    $scheduleFetchParameterSets = @(foreach ($groupId in $roleAssignableGroupIds) {
        $parameterSet = @{
            GroupEntityId       = $groupId
            AccessToken         = $AccessToken
            CollectorVersion    = $collectorVersion
            CollectedAt         = $collectedAt
            RequestHostOverride = $RequestHostOverride
        }
        if ($AllowlistOverride) { $parameterSet['AllowlistOverride'] = $AllowlistOverride }
        if ($SchemeOverride -ne 'https') { $parameterSet['SchemeOverride'] = $SchemeOverride }
        $parameterSet
    })

    $scheduleFetchResults = Invoke-EntraPostureBoundedParallel -CommandName 'Invoke-EntraPosturePimForGroupsScheduleFetch' `
        -ParameterSets $scheduleFetchParameterSets -ThrottleLimit $ScheduleFetchConcurrency

    $relationships = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $scheduleFetchResults.Count; $i++) {
        $fetchResult = $scheduleFetchResults[$i]
        if (-not $fetchResult.Success) {
            throw "Invoke-EntraPosturePimForGroupsCollector: fetching PIM-for-Groups schedules for group '$($roleAssignableGroupIds[$i])' failed: $($fetchResult.ErrorMessage)"
        }
        foreach ($r in @($fetchResult.Result.Relationships)) { $relationships.Add($r) }
    }

    return [ordered]@{
        Relationships = @($relationships.ToArray())
    }
}
