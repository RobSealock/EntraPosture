#Requires -Version 7.4

function Get-EntraPostureAgentUserCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAgentUserCollector's permission/coverage requirements.

        .DESCRIPTION
        User.ReadBasic.All is Microsoft's documented least-privileged permission for listing
        agent users (confirmed directly against the live "List agentUser objects" Graph
        reference page, re-fetched 2026-08-07). The per-user ownedObjects N+1 fetch (AGT-015)
        needs Directory.Read.All instead -- User.Read/User.ReadBasic.All are not sufficient for
        that specific relationship endpoint (confirmed against the live "List ownedObjects"
        reference page's own permissions table), and **that table also states Application
        permission is "Not supported" for ownedObjects at all**, a real Microsoft platform
        constraint, not an oversight: under this project's CertificateAppOnly auth mode,
        Directory.Read.All can still be granted as an application role and this specific
        relationship call will still fail (delegated-only), so AGT-015 evidence is structurally
        unavailable for any CertificateAppOnly run regardless of which permissions were granted.
        Feeds AGT-011/012 (correlated against DirectoryRoleAssignment/AzureRoleAssignment) and
        AGT-015 (ownedObjects, delegated-only) -- VNext build order item 13.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AgentUsers' `
        -RequiredPermissions @('User.ReadBasic.All', 'Directory.Read.All') `
        -EndpointsUsed @(
            '/v1.0/users/microsoft.graph.agentUser',
            '/v1.0/users/{userId}/ownedObjects'
        ) `
        -AffectedControlIds @('AGT-011', 'AGT-012', 'AGT-015') `
        -AffectedReportSections @('Agent Identities')
}

function Invoke-EntraPostureAgentUserOwnedGroupFetch {
    <#
        .SYNOPSIS
        Fetches one agent user's ownedObjects and normalizes only the Group-typed results to
        OwnerOf relationships -- the per-user unit of work
        Invoke-EntraPostureAgentUserCollector's AGT-015 N+1 fetch dispatches concurrently via
        Invoke-EntraPostureBoundedParallel.

        .DESCRIPTION
        ownedObjects returns any directoryObject type (applications, service principals,
        groups); AGT-015 only cares about group ownership (a group that may itself be referenced
        in a Conditional Access policy's includeGroups/excludeGroups), so non-group results are
        filtered out here at the normalization boundary rather than persisting owned objects this
        control will never read -- the same "don't persist evidence no control consumes"
        discipline this project applies to raw API responses generally.

        .PARAMETER AgentUserEntityId
        .PARAMETER AccessToken
        .PARAMETER CollectorVersion
        .PARAMETER CollectedAt
        .PARAMETER RequestHostOverride
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride

        .OUTPUTS
        Ordered dictionary: Relationships (OwnerOf[], Group-typed owned objects only).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$AgentUserEntityId,

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

    $ownedObjectsPath = "/v1.0/users/$AgentUserEntityId/ownedObjects"
    $rawOwnedObjects = Send-EntraPostureRequest @sendParams -Path $ownedObjectsPath -Method GET

    $groupOwnedObjects = @($rawOwnedObjects | Where-Object {
        $odataType = if ($_.Contains('@odata.type')) { [string]$_['@odata.type'] } else { $null }
        $odataType -eq '#microsoft.graph.group'
    })

    $relationships = foreach ($rawGroup in $groupOwnedObjects) {
        ConvertTo-EntraPostureOwnerOfRelationship -RawOwner ([ordered]@{ id = $AgentUserEntityId }) -OwnedEntityId ([string]$rawGroup['id']) `
            -CollectorVersion $CollectorVersion -SourceEndpoint $ownedObjectsPath -CollectedAt $CollectedAt
    }

    return [ordered]@{
        Relationships = @($relationships)
    }
}

function Invoke-EntraPostureAgentUserCollector {
    <#
        .SYNOPSIS
        Collects agent users and (VNext build order item 13, AGT-015) each agent user's
        group-owned objects, normalized to canonical Entity and Relationship records. Read-only:
        one paginated Graph GET call listing agent users, plus a bounded-concurrent ownedObjects
        fetch per agent user.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.
        .PARAMETER OwnedObjectFetchConcurrency
        Bounded concurrency for the per-agent-user ownedObjects fetch (default four).

        .OUTPUTS
        Ordered dictionary: Entities (AgentUser[]), Relationships (OwnerOf[]).
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
        [int]$OwnedObjectFetchConcurrency = 4
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

    $path = '/v1.0/users/microsoft.graph.agentUser'
    $rawAgentUsers = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $agentUserEntities = @(foreach ($rawAgentUser in $rawAgentUsers) {
        ConvertTo-EntraPostureAgentUserEntity -RawAgentUser $rawAgentUser -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    })

    $ownedObjectFetchParameterSets = @(foreach ($agentUserEntity in $agentUserEntities) {
        $parameterSet = @{
            AgentUserEntityId   = $agentUserEntity.entityId
            AccessToken         = $AccessToken
            CollectorVersion    = $collectorVersion
            CollectedAt         = $collectedAt
            RequestHostOverride = $RequestHostOverride
        }
        if ($AllowlistOverride) { $parameterSet['AllowlistOverride'] = $AllowlistOverride }
        if ($SchemeOverride -ne 'https') { $parameterSet['SchemeOverride'] = $SchemeOverride }
        $parameterSet
    })

    $ownedObjectFetchResults = Invoke-EntraPostureBoundedParallel -CommandName 'Invoke-EntraPostureAgentUserOwnedGroupFetch' `
        -ParameterSets $ownedObjectFetchParameterSets -ThrottleLimit $OwnedObjectFetchConcurrency

    $ownerRelationships = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $ownedObjectFetchResults.Count; $i++) {
        $fetchResult = $ownedObjectFetchResults[$i]
        if (-not $fetchResult.Success) {
            throw "Invoke-EntraPostureAgentUserCollector: fetching ownedObjects for agent user '$($agentUserEntities[$i].entityId)' failed: $($fetchResult.ErrorMessage)"
        }
        foreach ($r in @($fetchResult.Result.Relationships)) { $ownerRelationships.Add($r) }
    }

    return [ordered]@{
        Entities      = @($agentUserEntities)
        Relationships = @($ownerRelationships.ToArray())
    }
}
