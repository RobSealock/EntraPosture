#Requires -Version 7.4

function Get-EntraPostureRoleAssignmentScopeCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureRoleAssignmentScopeCollector's permission/coverage
        requirements.

        .DESCRIPTION
        RoleManagement.Read.Directory is the lowest of the permissions Microsoft's own "List
        unifiedRoleAssignments" reference page lists for the directory RBAC provider (confirmed
        live 2026-08-08) -- the same permission this project's DirectoryRoleAssignments collector
        already requests, so granting it once already covers both. New collector, VNext build
        order item 2's 109-row backlog continuation (batch 15, 2026-08-08) -- built specifically
        for CAP-011, the genuinely-new-evidence deferral recorded in `00-open-questions.md` §41:
        the existing DirectoryRoleAssignments collector's own endpoint
        (`/directoryRoles/{id}/members`) structurally cannot return administrative-unit-scoped
        role assignments, only this different endpoint can.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'RoleAssignmentScopes' `
        -RequiredPermissions @('RoleManagement.Read.Directory') `
        -EndpointsUsed @('/v1.0/roleManagement/directory/roleAssignments') `
        -AffectedControlIds @('CAP-011') `
        -AffectedReportSections @('Privileged Roles', 'Conditional Access')
}

function Invoke-EntraPostureRoleAssignmentScopeCollector {
    <#
        .SYNOPSIS
        Collects every directory RBAC role assignment (any scope), normalized to canonical
        RoleAssignmentScope Relationship records. Read-only: one allowlisted, paginated Graph GET
        call -- a single bulk list, not a per-role or per-administrative-unit N+1 fetch.

        .PARAMETER AccessToken
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Relationships (RoleAssignmentScope[]).
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

    $path = '/v1.0/roleManagement/directory/roleAssignments'
    $rawAssignments = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $relationships = foreach ($rawAssignment in $rawAssignments) {
        ConvertTo-EntraPostureRoleAssignmentScopeRelationship -RawRoleAssignment $rawAssignment `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Relationships = @($relationships)
    }
}
