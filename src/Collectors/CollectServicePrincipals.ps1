#Requires -Version 7.4

function Get-EntraPostureServicePrincipalCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureServicePrincipalCollector's permission/coverage
        requirements.

        .DESCRIPTION
        Application.Read.All (same permission family as Applications -- service principals are
        the same underlying Graph resource family) is Microsoft's documented least-privileged
        permission, and already covers the /servicePrincipals/{id}/owners and
        /servicePrincipals/{id}/ownedObjects endpoints too (same permission family, no separate
        scope needed). ENT-003 (owners N+1, every service principal) and ENT-008 (ownedObjects
        N+1, foreign service principals only) added 2026-08-08, VNext build order item 2 batch 6.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'ServicePrincipals' `
        -RequiredPermissions @('Application.Read.All') `
        -EndpointsUsed @(
            '/v1.0/servicePrincipals',
            '/v1.0/servicePrincipals/{spId}/owners',
            '/v1.0/servicePrincipals/{spId}/ownedObjects'
        ) `
        -AffectedControlIds @('MAI-002', 'MAI-003', 'ENT-006', 'ENT-007', 'ENT-011', 'ENT-012', 'ENT-001', 'ENT-003', 'ENT-008') `
        -AffectedReportSections @('Applications')
}

function Invoke-EntraPostureServicePrincipalOwnerFetch {
    <#
        .SYNOPSIS
        Fetches and normalizes one service principal's owners -- the per-principal unit of work
        Invoke-EntraPostureServicePrincipalCollector's ENT-003 N+1 fetch dispatches concurrently,
        called for every service principal (unlike the ownedObjects fetch below, which is scoped
        to foreign principals only).

        .PARAMETER ServicePrincipalEntityId
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
        [string]$ServicePrincipalEntityId,

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

    $ownersPath = "/v1.0/servicePrincipals/$ServicePrincipalEntityId/owners"
    $rawOwners = Send-EntraPostureRequest @sendParams -Path $ownersPath -Method GET

    $relationships = foreach ($rawOwner in $rawOwners) {
        ConvertTo-EntraPostureOwnerOfRelationship -RawOwner $rawOwner -OwnedEntityId $ServicePrincipalEntityId `
            -CollectorVersion $CollectorVersion -SourceEndpoint $ownersPath -CollectedAt $CollectedAt
    }

    return [ordered]@{
        Relationships = @($relationships)
    }
}

function Invoke-EntraPostureServicePrincipalOwnedObjectFetch {
    <#
        .SYNOPSIS
        Fetches one foreign service principal's ownedObjects and normalizes every result to an
        OwnerOf relationship (the service principal as owner, not owned) -- the per-principal
        unit of work Invoke-EntraPostureServicePrincipalCollector's ENT-008 N+1 fetch dispatches
        concurrently, scoped to foreign service principals only (the caller filters before
        building parameter sets; this function itself does not re-check foreign-ness).

        .DESCRIPTION
        Unlike CollectAgentUsers.ps1's ownedObjects fetch (AGT-015, filtered to group-typed
        results only), this keeps every owned object type -- ENT-008 ("Foreign Enterprise Apps
        Owning Objects") is deliberately not scoped to one object type, per the matrix's own
        canonical registry consolidating EF-EAP-008/009/011's separate "ownership over app
        registrations"/"of other service principals"/"owns app registration" signals into one
        finding, the same "one canonical ID, not fragmented by object type" pattern
        00-open-questions.md already documented for GRP-005.

        .PARAMETER ServicePrincipalEntityId
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
        [string]$ServicePrincipalEntityId,

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

    $ownedObjectsPath = "/v1.0/servicePrincipals/$ServicePrincipalEntityId/ownedObjects"
    $rawOwnedObjects = Send-EntraPostureRequest @sendParams -Path $ownedObjectsPath -Method GET

    $relationships = foreach ($rawOwnedObject in $rawOwnedObjects) {
        ConvertTo-EntraPostureOwnerOfRelationship -RawOwner ([ordered]@{ id = $ServicePrincipalEntityId }) -OwnedEntityId ([string]$rawOwnedObject['id']) `
            -CollectorVersion $CollectorVersion -SourceEndpoint $ownedObjectsPath -CollectedAt $CollectedAt
    }

    return [ordered]@{
        Relationships = @($relationships)
    }
}

function Invoke-EntraPostureServicePrincipalCollector {
    <#
        .SYNOPSIS
        Collects service principals (enterprise apps and managed identities together) and
        (VNext build order item 2 batch 6) their owners (every principal, ENT-003) and owned
        objects (foreign principals only, ENT-008), normalized to canonical Entity and
        Relationship records -- entityType 'ServicePrincipal' or 'ManagedIdentity' depending on
        each record's own servicePrincipalType (see the normalizer's own DESCRIPTION). Read-only:
        one paginated Graph GET call, plus two bounded-concurrent N+1 fetch rounds.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.
        .PARAMETER OwnerFetchConcurrency
        Bounded concurrency for both N+1 fetch rounds (default four).

        .OUTPUTS
        Ordered dictionary: Entities (ServicePrincipal[] and/or ManagedIdentity[], mixed),
        Relationships (OwnerOf[]).
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

    $path = '/v1.0/servicePrincipals'
    $rawServicePrincipals = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = @(foreach ($rawServicePrincipal in $rawServicePrincipals) {
        ConvertTo-EntraPostureServicePrincipalEntity -RawServicePrincipal $rawServicePrincipal -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    })

    $ownerFetchParameterSets = @(foreach ($principal in $entities) {
        $parameterSet = @{
            ServicePrincipalEntityId = $principal.entityId
            AccessToken              = $AccessToken
            CollectorVersion         = $collectorVersion
            CollectedAt              = $collectedAt
            RequestHostOverride      = $RequestHostOverride
        }
        if ($AllowlistOverride) { $parameterSet['AllowlistOverride'] = $AllowlistOverride }
        if ($SchemeOverride -ne 'https') { $parameterSet['SchemeOverride'] = $SchemeOverride }
        $parameterSet
    })
    $ownerFetchResults = Invoke-EntraPostureBoundedParallel -CommandName 'Invoke-EntraPostureServicePrincipalOwnerFetch' `
        -ParameterSets $ownerFetchParameterSets -ThrottleLimit $OwnerFetchConcurrency

    $relationships = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $ownerFetchResults.Count; $i++) {
        $fetchResult = $ownerFetchResults[$i]
        if (-not $fetchResult.Success) {
            throw "Invoke-EntraPostureServicePrincipalCollector: fetching owners for service principal '$($entities[$i].entityId)' failed: $($fetchResult.ErrorMessage)"
        }
        foreach ($r in @($fetchResult.Result.Relationships)) { $relationships.Add($r) }
    }

    $foreignPrincipals = @($entities | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.properties.appOwnerOrganizationId) -and
        [string]$_.properties.appOwnerOrganizationId -ne $TenantScope
    })
    $ownedObjectFetchParameterSets = @(foreach ($principal in $foreignPrincipals) {
        $parameterSet = @{
            ServicePrincipalEntityId = $principal.entityId
            AccessToken              = $AccessToken
            CollectorVersion         = $collectorVersion
            CollectedAt              = $collectedAt
            RequestHostOverride      = $RequestHostOverride
        }
        if ($AllowlistOverride) { $parameterSet['AllowlistOverride'] = $AllowlistOverride }
        if ($SchemeOverride -ne 'https') { $parameterSet['SchemeOverride'] = $SchemeOverride }
        $parameterSet
    })
    $ownedObjectFetchResults = Invoke-EntraPostureBoundedParallel -CommandName 'Invoke-EntraPostureServicePrincipalOwnedObjectFetch' `
        -ParameterSets $ownedObjectFetchParameterSets -ThrottleLimit $OwnerFetchConcurrency

    for ($i = 0; $i -lt $ownedObjectFetchResults.Count; $i++) {
        $fetchResult = $ownedObjectFetchResults[$i]
        if (-not $fetchResult.Success) {
            throw "Invoke-EntraPostureServicePrincipalCollector: fetching ownedObjects for foreign service principal '$($foreignPrincipals[$i].entityId)' failed: $($fetchResult.ErrorMessage)"
        }
        foreach ($r in @($fetchResult.Result.Relationships)) { $relationships.Add($r) }
    }

    return [ordered]@{
        Entities      = @($entities)
        Relationships = @($relationships.ToArray())
    }
}
