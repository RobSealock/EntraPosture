#Requires -Version 7.4

function Get-EntraPostureAzureRoleAssignmentCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAzureRoleAssignmentCollector's permission/coverage
        requirements (input to Test-EntraPosturePreflight).

        .DESCRIPTION
        Microsoft.Authorization/roleAssignments/read is the documented least-privileged Azure
        action for listing RBAC role assignments at a scope; typically granted via the built-in
        Reader role. AffectedControlIds was empty until 2026-08-08 -- a real, pre-existing
        coverage-accuracy gap caught while wiring MAI-002/003: AGT-005/009/012/014 and MAI-003
        all correlate against AzureRoleAssignment evidence directly (via properties.principalId,
        not a relationship), but this collector never declared that dependency, so coverage.json
        could report those controls' coverage as Complete even when this specific collector's
        own evidence was Denied/Unavailable -- the same "missing evidence never becomes a clean
        result" principle this project applies everywhere else, now applied here too.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AzureRoleAssignments' `
        -RequiredPermissions @('Microsoft.Authorization/roleAssignments/read') `
        -EndpointsUsed @('/{scope}/providers/Microsoft.Authorization/roleAssignments') `
        -AffectedControlIds @('AGT-005', 'AGT-009', 'AGT-012', 'AGT-014', 'MAI-003', 'ENT-007', 'ENT-012', 'USR-008', 'USR-009') `
        -AffectedReportSections @('Azure RBAC')
}

function Invoke-EntraPostureAzureRoleAssignmentCollector {
    <#
        .SYNOPSIS
        Collects Azure RBAC role assignments at one ARM scope, normalized to canonical Entity
        records (including inherited-vs-direct correlation -- see the normalizer's own
        DESCRIPTION). Read-only: one allowlisted ARM GET call.

        .DESCRIPTION
        The caller supplies exactly one scope per call (e.g. '/subscriptions/{id}') --
        orchestration is responsible for calling this once per discovered scope (subscriptions
        and management groups, from Invoke-EntraPostureAzureSubscriptionCollector /
        Invoke-EntraPostureAzureManagementGroupCollector), not this function fanning out
        internally.

        .PARAMETER AccessToken
        An Azure Resource Manager-audience access token.

        .PARAMETER Scope
        ARM scope path, e.g. '/subscriptions/00000000-0000-0000-0000-000000000000'.

        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        Test-only passthrough to Send-EntraPostureRequest.

        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'management.azure.com'.

        .OUTPUTS
        Ordered dictionary: Entities (AzureRoleAssignment[]).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$Scope,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https',

        [Parameter()]
        [string]$RequestHostOverride = 'management.azure.com'
    )

    $collectorVersion = (Get-EntraPostureToolVersionInfo).ToolVersion
    $collectedAt = (Get-Date).ToUniversalTime().ToString('o')

    $sendParams = @{
        RequestHost = $RequestHostOverride
        ApiStability = 'Stable'
        AccessToken  = $AccessToken
    }
    if ($AllowlistOverride) { $sendParams['AllowlistOverride'] = $AllowlistOverride }
    if ($SchemeOverride -ne 'https') { $sendParams['SchemeOverride'] = $SchemeOverride }

    $path = "$Scope/providers/Microsoft.Authorization/roleAssignments"
    $rawAssignments = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawAssignment in $rawAssignments) {
        ConvertTo-EntraPostureAzureRoleAssignmentEntity -RawAssignment $rawAssignment -QueriedScope $Scope -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
