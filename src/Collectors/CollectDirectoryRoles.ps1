#Requires -Version 7.4

function Get-EntraPostureDirectoryRoleCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureDirectoryRoleCollector's permission/coverage
        requirements (input to Test-EntraPosturePreflight).

        .DESCRIPTION
        RoleManagement.Read.Directory is Microsoft's documented least-privileged application
        role for reading directoryRoles and their members. Feeds the 'PRIV-001' relationship
        control (Global Administrator active-membership-count check) and the 'Privileged Roles'
        report section. Also feeds 'PIM-002' (Phase 7, Tier-0 standing assignments outside PIM)
        -- that control cross-references this collector's DirectoryRoleAssignment relationships
        against PimEligibility's PimEligible relationships, so both collectors are coverage
        requirements for PIM-002. PIM-003 through PIM-009 (VNext build order item 8) also read
        this collector's DirectoryRole entities (to resolve the curated Tier-0 role set), though
        not its relationships -- AffectedControlIds is load-bearing, not descriptive (see
        CollectTenantPolicies.ps1's own docstring for why), so all seven are listed here too.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'DirectoryRoleAssignments' `
        -RequiredPermissions @('RoleManagement.Read.Directory') `
        -EndpointsUsed @('/v1.0/directoryRoles', '/v1.0/directoryRoles/{roleId}/members') `
        -AffectedControlIds @(
            'PRIV-001', 'PIM-002', 'CA-001', 'CA-002', 'PIM-003', 'PIM-004', 'PIM-005', 'PIM-006', 'PIM-007', 'PIM-008', 'PIM-009', 'CAP-010',
            'AGT-004', 'AGT-008', 'AGT-011', 'AGT-013', 'MAI-002',
            'ENT-006', 'ENT-011', 'USR-007'
        ) `
        -AffectedReportSections @('Privileged Roles')
}

function Invoke-EntraPostureDirectoryRoleCollector {
    <#
        .SYNOPSIS
        Collects every activated directory role and its current active members, normalized to
        canonical Entity/Relationship records. Read-only: two allowlisted Graph GET calls per
        role (list roles, then list each role's members).

        .DESCRIPTION
        Graph's /v1.0/directoryRoles only returns roles that have been activated in the tenant
        (i.e. have or have had at least one member) -- an inactive built-in role template never
        appears here and is correctly absent from the resulting entity set, not an error.

        .PARAMETER AccessToken
        A Graph-audience access token.

        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        Test-only passthrough to Send-EntraPostureRequest -- see that function's parameter
        docs. Production orchestration code must never pass either.

        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'. Production orchestration code
        must never pass this -- exists only so tests can point this collector at a local mock
        server, matching Send-EntraPostureRequest's own -SchemeOverride precedent.

        .OUTPUTS
        Ordered dictionary: Entities (DirectoryRole[]), Relationships (DirectoryRoleAssignment[]).
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
        [string]$RequestHostOverride = 'graph.microsoft.com'
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

    $rawRoles = Send-EntraPostureRequest @sendParams -Path '/v1.0/directoryRoles' -Method GET

    $entities = [System.Collections.Generic.List[object]]::new()
    $relationships = [System.Collections.Generic.List[object]]::new()

    foreach ($rawRole in $rawRoles) {
        $roleEntity = ConvertTo-EntraPostureDirectoryRoleEntity -RawRole $rawRole -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint '/v1.0/directoryRoles' -CollectedAt $collectedAt
        $entities.Add($roleEntity)

        $roleInstanceId = [string]$rawRole['id']
        $membersPath = "/v1.0/directoryRoles/$roleInstanceId/members"
        $rawMembers = Send-EntraPostureRequest @sendParams -Path $membersPath -Method GET

        foreach ($rawMember in $rawMembers) {
            $relationships.Add((ConvertTo-EntraPostureDirectoryRoleAssignmentRelationship -RawMember $rawMember `
                -RoleEntityId $roleEntity.entityId -CollectorVersion $collectorVersion -SourceEndpoint $membersPath -CollectedAt $collectedAt))
        }
    }

    return [ordered]@{
        Entities      = @($entities.ToArray())
        Relationships = @($relationships.ToArray())
    }
}
