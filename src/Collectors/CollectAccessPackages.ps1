#Requires -Version 7.4

function Get-EntraPostureAccessPackageCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAccessPackageCollector's permission/coverage
        requirements.

        .DESCRIPTION
        v.next build order item 11 (EM-001/EM-002), admitted into v1 scope by the deviation
        record in 00-open-questions.md item 28. EntitlementManagement.Read.All -- confirmed
        directly against Microsoft's "List accessPackages" and "List accessPackageAssignments"
        operation pages as least-privileged, with Global Reader explicitly listed among
        supported built-in Entra roles for both -- no elevated-role coverage gap to report here,
        unlike AR-001's role-scoped access reviews. The per-package detail fetch
        (`GET .../accessPackages/{id}?$expand=resourceRoleScopes(...),assignmentPolicies`)
        showed a discrepancy in Microsoft's own docs worth flagging: its permissions TABLE states
        EntitlementManagement.Read.All is least-privileged (consistent with every other
        operation on this page), but its prose "Tip" section references
        EntitlementManagement.ReadWrite.All in a way that reads as contradictory. Trusted the
        structured table over the prose, the same "trust the more authoritative source" judgment
        this project already applied in AR-002 (resource-page enum over a differing example
        value).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AccessPackages' `
        -RequiredPermissions @('EntitlementManagement.Read.All') `
        -EndpointsUsed @(
            '/v1.0/identityGovernance/entitlementManagement/accessPackages',
            '/v1.0/identityGovernance/entitlementManagement/accessPackages/{accessPackageId}',
            '/v1.0/identityGovernance/entitlementManagement/assignments'
        ) `
        -AffectedControlIds @('EM-001', 'EM-002') `
        -AffectedReportSections @('Entitlement Management')
}

function Invoke-EntraPostureAccessPackageDetailFetch {
    <#
        .SYNOPSIS
        Fetches and normalizes one access package's resourceRoleScopes and assignmentPolicies in
        a single per-package GET -- the per-package unit of work
        Invoke-EntraPostureAccessPackageCollector dispatches concurrently via
        Invoke-EntraPostureBoundedParallel (same pattern as
        Invoke-EntraPostureGroupTransitiveMemberFetch / Invoke-EntraPostureAccessReviewInstanceFetch).

        .DESCRIPTION
        `$expand=resourceRoleScopes($expand=role,scope),assignmentPolicies` combines both
        relationships Microsoft's own accessPackage resource page confirms support $expand into
        one request, avoiding a second per-package N+1 level (unlike AR-002's genuinely
        three-level definitions -> instances -> decisions nesting, this is a flat one-level N+1:
        one call per package, full detail in that single response).

        .PARAMETER AccessPackageId
        .PARAMETER TenantScope
        .PARAMETER AccessToken
        .PARAMETER CollectorVersion
        .PARAMETER CollectedAt
        .PARAMETER RequestHostOverride
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride

        .OUTPUTS
        Ordered dictionary: Entities (AccessPackage[1] + AccessPackageAssignmentPolicy[]).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$AccessPackageId,

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
        RequestHost     = $RequestHostOverride
        ApiStability    = 'Stable'
        AccessToken     = $AccessToken
        QueryParameters = @{
            '$expand' = 'resourceRoleScopes($expand=role,scope),assignmentPolicies'
        }
    }
    if ($AllowlistOverride) { $sendParams['AllowlistOverride'] = $AllowlistOverride }
    if ($SchemeOverride -ne 'https') { $sendParams['SchemeOverride'] = $SchemeOverride }

    $path = "/v1.0/identityGovernance/entitlementManagement/accessPackages/$AccessPackageId"
    # Single-object GET (no top-level 'value' array) still returns a comma-protected 1-element
    # array -- Send-EntraPostureRequest's own documented behavior for a non-list response,
    # same pattern as Invoke-EntraPostureCrossTenantAccessPolicyCollector's [0] indexing.
    $rawPackage = (Send-EntraPostureRequest @sendParams -Path $path -Method GET)[0]

    $packageEntity = ConvertTo-EntraPostureAccessPackageEntity -RawPackage $rawPackage -TenantScope $TenantScope `
        -CollectorVersion $CollectorVersion -SourceEndpoint $path -CollectedAt $CollectedAt

    $rawPolicies = @(if ($rawPackage.Contains('assignmentPolicies')) { $rawPackage['assignmentPolicies'] } else { @() })
    $policyEntities = @(foreach ($rawPolicy in $rawPolicies) {
        ConvertTo-EntraPostureAccessPackageAssignmentPolicyEntity -RawPolicy $rawPolicy -AccessPackageId $AccessPackageId `
            -TenantScope $TenantScope -CollectorVersion $CollectorVersion -SourceEndpoint $path -CollectedAt $CollectedAt
    })

    return [ordered]@{
        Entities = @(@($packageEntity) + $policyEntities)
    }
}

function Invoke-EntraPostureAccessPackageCollector {
    <#
        .SYNOPSIS
        Collects every access package (with its resource roles and assignment policies) and
        every tenant-wide access package assignment, normalized to canonical Entity records.
        Read-only: one paginated Graph GET listing packages, a bounded-concurrent per-package
        detail GET, and one paginated tenant-wide GET for assignments.

        .DESCRIPTION
        Assignments are fetched ONCE, tenant-wide (`GET .../entitlementManagement/assignments`,
        confirmed directly against Microsoft's own "List accessPackageAssignments" operation page
        to return "all the assignments, current as well as expired, that the caller has access
        to read, across all catalogs and access packages" for a directory-wide caller -- no
        per-package N+1 needed for this half, unlike the package/policy half above). `$expand=
        accessPackage` is used only to recover each assignment's parent accessPackageId inline
        (`target` is deliberately never requested -- see NormalizeAccessPackageAssignment.ps1's
        own DESCRIPTION for the redaction rationale).

        Returns a single, mixed-entityType Entities array (AccessPackage,
        AccessPackageAssignmentPolicy, AccessPackageAssignment) -- CollectAndSeal.ps1 routes each
        record to its own evidence file by the record's own entityType, the same pattern
        Invoke-EntraPostureAccessReviewDefinitionCollector already established for AR-002.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.
        .PARAMETER DetailFetchConcurrency
        Bounded concurrency for the per-package detail fetch (default four, matching every other
        bounded-concurrent collector in this project).

        .OUTPUTS
        Ordered dictionary: Entities (AccessPackage[] + AccessPackageAssignmentPolicy[] +
        AccessPackageAssignment[]).
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
        [int]$DetailFetchConcurrency = 4
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

    $listPath = '/v1.0/identityGovernance/entitlementManagement/accessPackages'
    $rawPackages = Send-EntraPostureRequest @sendParams -Path $listPath -Method GET

    $packageIds = @(foreach ($rawPackage in $rawPackages) {
        if (-not $rawPackage.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$rawPackage['id'])) {
            throw 'Invoke-EntraPostureAccessPackageCollector: raw access package record has no id.'
        }
        [string]$rawPackage['id']
    })

    $detailFetchParameterSets = @(foreach ($packageId in $packageIds) {
        $parameterSet = @{
            AccessPackageId     = $packageId
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

    $detailFetchResults = Invoke-EntraPostureBoundedParallel -CommandName 'Invoke-EntraPostureAccessPackageDetailFetch' `
        -ParameterSets $detailFetchParameterSets -ThrottleLimit $DetailFetchConcurrency

    $detailEntities = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $detailFetchResults.Count; $i++) {
        $fetchResult = $detailFetchResults[$i]
        if (-not $fetchResult.Success) {
            throw "Invoke-EntraPostureAccessPackageCollector: fetching detail for access package '$($packageIds[$i])' failed: $($fetchResult.ErrorMessage)"
        }
        foreach ($e in @($fetchResult.Result.Entities)) { $detailEntities.Add($e) }
    }

    $assignmentsSendParams = $sendParams.Clone()
    $assignmentsSendParams['QueryParameters'] = @{ '$expand' = 'accessPackage' }
    $assignmentsPath = '/v1.0/identityGovernance/entitlementManagement/assignments'
    $rawAssignments = Send-EntraPostureRequest @assignmentsSendParams -Path $assignmentsPath -Method GET

    $assignmentEntities = @(foreach ($rawAssignment in $rawAssignments) {
        ConvertTo-EntraPostureAccessPackageAssignmentEntity -RawAssignment $rawAssignment -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $assignmentsPath -CollectedAt $collectedAt
    })

    return [ordered]@{
        Entities = @($detailEntities.ToArray() + $assignmentEntities)
    }
}
