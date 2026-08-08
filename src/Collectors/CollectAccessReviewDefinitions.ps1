#Requires -Version 7.4

function Get-EntraPostureAccessReviewDefinitionCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAccessReviewDefinitionCollector's permission/coverage
        requirements.

        .DESCRIPTION
        AccessReview.Read.All -- confirmed insufficient under Global Reader alone for
        role-assignment-scoped reviews specifically (00-permission-report-matrix.md: Security
        Reader / Identity Governance Administrator / Privileged Role Administrator / Security
        Administrator only), a documented v1 coverage gap, not an oversight. Feeds AR-001
        (Phase 7) and, per the two additional endpoints below (VNext build order item 9), AR-002
        -- both instances and decisions are covered by the same AccessReview.Read.All scope
        (confirmed directly against Microsoft's "List instances"/"List decisions" operation
        pages), so no new permission scope was needed.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AccessReviewDefinitions' `
        -RequiredPermissions @('AccessReview.Read.All') `
        -EndpointsUsed @(
            '/v1.0/identityGovernance/accessReviews/definitions',
            '/v1.0/identityGovernance/accessReviews/definitions/{definitionId}/instances',
            '/v1.0/identityGovernance/accessReviews/definitions/{definitionId}/instances/{instanceId}/decisions'
        ) `
        -AffectedControlIds @('AR-001', 'AR-002') `
        -AffectedReportSections @('Access Reviews')
}

function Invoke-EntraPostureAccessReviewInstanceFetch {
    <#
        .SYNOPSIS
        Fetches, aggregates, and normalizes one AccessReviewDefinition's most recent instance --
        the per-definition unit of work Invoke-EntraPostureAccessReviewDefinitionCollector's
        AR-002 N+1 fetch dispatches concurrently via Invoke-EntraPostureBoundedParallel (same
        pattern as Invoke-EntraPostureGroupTransitiveMemberFetch, VNext build order item 6).

        .DESCRIPTION
        Two sequential Graph calls per definition: list instances, then (only for the most
        recent one, by startDateTime descending) list that instance's decisions. Only the most
        recent instance is evaluated -- a deliberate scope decision (see AR-002.psd1's
        provenance notes) to bound evidence volume; the matrix itself leaves "historical
        instances too" as an open, unresolved Phase 7 question. A definition with zero instances
        yet (e.g. Draft, never started a cycle) produces no entity at all, not an empty/error
        one.

        Extracted into its own standalone function for the same reason
        Invoke-EntraPostureGroupTransitiveMemberFetch was: a bounded runspace pool invokes a
        named, already-loaded function per unit of work. Side-effect-free with respect to
        anything outside its own parameters/return value.

        .PARAMETER DefinitionId
        .PARAMETER TenantScope
        .PARAMETER AccessToken
        .PARAMETER CollectorVersion
        .PARAMETER CollectedAt
        .PARAMETER RequestHostOverride
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride

        .OUTPUTS
        Ordered dictionary: Entities (AccessReviewInstance[], zero or one element).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$DefinitionId,

        [Parameter(Mandatory)]
        [string]$TenantScope,

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

    # No @() wrapper at these two call sites -- Send-EntraPostureRequest already
    # comma-protects its return (see its own trailing comment: `return ,$results.ToArray()`);
    # wrapping the call site in @() too double-wraps an empty result into a 1-element array
    # containing the real empty array, confirmed directly (Count of 1 instead of 0) while
    # building this collector's tests -- the same bug class as EvidenceFileRegistry.ps1's own
    # header comment on Get-EntraPostureEntity/Get-EntraPostureRelationship.
    $instancesPath = "/v1.0/identityGovernance/accessReviews/definitions/$DefinitionId/instances"
    $rawInstances = Send-EntraPostureRequest @sendParams -Path $instancesPath -Method GET

    if (@($rawInstances).Count -eq 0) {
        return [ordered]@{ Entities = @() }
    }

    $mostRecentInstance = @($rawInstances | Sort-Object -Property @{ Expression = { $_['startDateTime'] }; Descending = $true } -Stable)[0]
    $instanceId = [string]$mostRecentInstance['id']

    $decisionsPath = "/v1.0/identityGovernance/accessReviews/definitions/$DefinitionId/instances/$instanceId/decisions"
    $rawDecisions = Send-EntraPostureRequest @sendParams -Path $decisionsPath -Method GET

    $entity = ConvertTo-EntraPostureAccessReviewInstanceEntity -RawInstance $mostRecentInstance -DefinitionId $DefinitionId `
        -RawDecisions $rawDecisions -TenantScope $TenantScope -CollectorVersion $CollectorVersion -SourceEndpoint $decisionsPath -CollectedAt $CollectedAt

    return [ordered]@{
        Entities = @($entity)
    }
}

function Invoke-EntraPostureAccessReviewDefinitionCollector {
    <#
        .SYNOPSIS
        Collects access review definitions and (VNext build order item 9) each definition's most
        recent instance/decision-aggregate, normalized to canonical Entity records. Read-only:
        one paginated Graph GET call listing definitions, plus a bounded-concurrent pair of calls
        (instances, then decisions) per definition.

        .DESCRIPTION
        Returns a single, mixed-entityType Entities array (AccessReviewDefinition and
        AccessReviewInstance) -- CollectAndSeal.ps1's evidence-file write step routes each record
        to its own file by the record's own entityType, not by collector name (confirmed against
        its own filtering logic before choosing this shape), the same pattern already relied on
        implicitly by every other collector's Entities/Relationships split.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.
        .PARAMETER InstanceFetchConcurrency
        Bounded concurrency for the per-definition instance/decisions fetch (default four,
        matching Invoke-EntraPostureGroupCollector's own default).

        .OUTPUTS
        Ordered dictionary: Entities (AccessReviewDefinition[] + AccessReviewInstance[]).
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
        [int]$InstanceFetchConcurrency = 4
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

    $path = '/v1.0/identityGovernance/accessReviews/definitions'
    $rawDefinitions = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $definitionEntities = @(foreach ($rawDefinition in $rawDefinitions) {
        ConvertTo-EntraPostureAccessReviewDefinitionEntity -RawDefinition $rawDefinition -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    })

    $instanceFetchParameterSets = @(foreach ($definitionEntity in $definitionEntities) {
        $parameterSet = @{
            DefinitionId        = $definitionEntity.entityId
            TenantScope         = $TenantScope
            AccessToken         = $AccessToken
            CollectorVersion    = $collectorVersion
            CollectedAt         = $collectedAt
            RequestHostOverride = $RequestHostOverride
        }
        if ($AllowlistOverride) { $parameterSet['AllowlistOverride'] = $AllowlistOverride }
        if ($SchemeOverride -ne 'https') { $parameterSet['SchemeOverride'] = $SchemeOverride }
        $parameterSet
    })

    $instanceFetchResults = Invoke-EntraPostureBoundedParallel -CommandName 'Invoke-EntraPostureAccessReviewInstanceFetch' `
        -ParameterSets $instanceFetchParameterSets -ThrottleLimit $InstanceFetchConcurrency

    $instanceEntities = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $instanceFetchResults.Count; $i++) {
        $fetchResult = $instanceFetchResults[$i]
        if (-not $fetchResult.Success) {
            throw "Invoke-EntraPostureAccessReviewDefinitionCollector: fetching instance/decisions for definition '$($definitionEntities[$i].entityId)' failed: $($fetchResult.ErrorMessage)"
        }
        foreach ($e in @($fetchResult.Result.Entities)) { $instanceEntities.Add($e) }
    }

    return [ordered]@{
        Entities = @($definitionEntities + $instanceEntities.ToArray())
    }
}
