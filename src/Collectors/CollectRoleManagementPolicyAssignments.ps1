#Requires -Version 7.4

function Get-EntraPostureRoleManagementPolicyAssignmentCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureRoleManagementPolicyAssignmentCollector's permission/
        coverage requirements.

        .DESCRIPTION
        RoleManagementPolicy.Read.Directory, confirmed directly against Microsoft Graph's "List
        roleManagementPolicyAssignments" documentation (least-privileged delegated/application
        permission, re-fetched 2026-08-07) -- a genuinely new permission this project didn't
        already hold, distinct from the similarly-named RoleManagement.Read.Directory this
        project's DirectoryRoleAssignments/PimEligibility collectors already use (confirmed two
        separate scopes on Microsoft's own permissions table, not a typo). Global Reader is a
        confirmed supported built-in role for read access to this specific operation (alongside
        Security Operator, Security Reader, Security Administrator, Privileged Role
        Administrator) -- no Global Reader coverage gap here, unlike NamedLocations/
        AuthenticationStrengthPolicies (build order items 4/5).

        Fed AUTHCTX-001/AUTHCTX-002 (build order item 7) first, deliberately scoped broadly
        enough from the start to also feed PIM-003 through PIM-009 (build order item 8, done
        2026-08-07) without a second evidence-domain pass -- VNext.md's own text named this as
        the intended reuse, not speculative scope creep. AffectedControlIds is load-bearing, not
        descriptive (see CollectTenantPolicies.ps1's own docstring for why -- confirmed the hard
        way during item 2): every control reading this collector's evidence must be listed here
        or it is wrongly marked NotEvaluated regardless of real coverage.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'RoleManagementPolicyAssignments' `
        -RequiredPermissions @('RoleManagementPolicy.Read.Directory') `
        -EndpointsUsed @('/v1.0/policies/roleManagementPolicyAssignments') `
        -AffectedControlIds @('AUTHCTX-001', 'AUTHCTX-002', 'PIM-003', 'PIM-004', 'PIM-005', 'PIM-006', 'PIM-007', 'PIM-008', 'PIM-009') `
        -AffectedReportSections @('Privileged Roles', 'Conditional Access')
}

function Invoke-EntraPostureRoleManagementPolicyAssignmentCollector {
    <#
        .SYNOPSIS
        Collects every Microsoft Entra directory role's PIM activation-policy assignment, with
        its policy and rules expanded inline, normalized to canonical Entity records. Read-only:
        one allowlisted, paginated Graph GET call (no N+1 -- $expand=policy($expand=rules)
        returns everything needed in the same response, confirmed directly against Microsoft's
        own documented example).

        .DESCRIPTION
        Scoped with $filter=scopeId eq '/' and scopeType eq 'DirectoryRole' -- Entra directory
        roles only, not PIM for Groups or Azure resource roles (both out of this project's
        current evidence scope; PIM for Groups specifically is still pending the same BETA-status
        triage as agent identities, per 00-open-questions.md).

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (RoleManagementPolicyAssignment[]).
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
        RequestHost     = $RequestHostOverride
        ApiStability    = 'Stable'
        AccessToken     = $AccessToken
        QueryParameters = @{
            '$filter' = "scopeId eq '/' and scopeType eq 'DirectoryRole'"
            '$expand' = 'policy($expand=rules)'
        }
    }
    if ($AllowlistOverride) { $sendParams['AllowlistOverride'] = $AllowlistOverride }
    if ($SchemeOverride -ne 'https') { $sendParams['SchemeOverride'] = $SchemeOverride }

    $path = '/v1.0/policies/roleManagementPolicyAssignments'
    $rawAssignments = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawAssignment in $rawAssignments) {
        ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity -RawAssignment $rawAssignment -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
