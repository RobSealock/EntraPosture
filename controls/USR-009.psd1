@{
    <#
        VNext build order item 2, the 109-row backlog continuation (batch 13, 2026-08-08). New
        curated Tier-0 Azure role list -- see TierZeroAzureRoleList.ps1's own header comment for
        the independent verification behind it. Keys deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'USR-009'
    version     = '1.0.0'
    title       = 'Least Privilege Principle Not Applied (Azure)'
    description = 'Checks whether too many enabled users hold a curated Tier-0 Azure RBAC role, directly or through a group''s membership. Fails at 8 or more such users.'
    rationale   = 'A large population of standing Tier-0 Azure role holders (Owner, User Access Administrator, or Role Based Access Control Administrator) is a wide blast radius across every resource in scope -- every one of those accounts is an equally attractive target for an attacker seeking full subscription control.'
    severity    = 2
    category    = 'Users'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AzureRoleAssignment', 'User', 'TransitiveMemberOf')
    requiredPermissions     = @(
        @{ scope = 'Microsoft.Authorization/roleAssignments/read'; confirmed = $true }
        @{ scope = 'User.Read.All'; confirmed = $true }
        @{ scope = 'Group.Read.All'; confirmed = $true }
        @{ scope = 'GroupMember.Read.All'; confirmed = $true }
    )

    applicability = 'A single tenant-scoped result. Requires -ArmScope to have been supplied at collection time (Azure RBAC evidence is discovery-only otherwise); NotApplicable is not a distinct branch here since an empty AzureRoleAssignment set (no -ArmScope) simply yields a count of zero, Pass.'

    reasonCodes = @(
        @{ code = 'USR-009-EXCESSIVE-TIER-ZERO-USERS';    resultStatus = 'Fail';         description = '8 or more enabled users hold a curated Tier-0 Azure RBAC role, directly or through a group.' }
        @{ code = 'USR-009-TIER-ZERO-USERS-WITHIN-RANGE'; resultStatus = 'Pass';        description = 'Fewer than 8 enabled users hold a curated Tier-0 Azure RBAC role.' }
        @{ code = 'USR-009-EVIDENCE-NOT-COLLECTED';       resultStatus = 'NotEvaluated'; description = 'AzureRoleAssignment, User, or TransitiveMemberOf evidence was not fully collected for this snapshot.' }
        @{ code = 'USR-009-EVALUATOR-ERROR';              resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Exactly one tenant-scoped result. Fail if 8 or more enabled users (counted once each, deduplicated across direct and group-derived membership) hold a curated Tier-0 Azure RBAC role assignment; Pass otherwise, including when no Azure RBAC evidence was collected at all (a subscription/management-group scope was never supplied). Only User principals are counted -- service principal, managed identity, and agent identity Tier-0 Azure role holding are separate findings (ENT-007/012, MAI-003, AGT-005/009/012). NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureAzureLeastPrivilegeControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review the Tier-0 Azure role holder population and remove standing access from users who do not need it; scope any remaining assignments as narrowly as possible (specific resource groups, not subscription root) and prefer time-bound PIM-for-Azure-resources activation where available.'

    references = @(
        'https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/privileged'
        'https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-list-rest'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic -- the Tier-0 Azure role list was independently curated by reading each candidate role''s own live JSON permission grant (Owner/User Access Administrator/Role Based Access Control Administrator included; Contributor and Reservations Administrator excluded, both with specific documented reasons -- see TierZeroAzureRoleList.ps1). 8-user threshold and fixed severity match this project''s own single-threshold model, not EntraFalcon''s graduated confidence bands. Reuses entirely pre-existing evidence -- zero new collection.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'USR-009' }
    )

    baselineDependency = $null
}
