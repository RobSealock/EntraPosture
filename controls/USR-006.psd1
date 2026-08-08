@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Keys
        deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'USR-006'
    version     = '1.0.0'
    title       = 'Least Privilege Principle Not Applied (Entra ID)'
    description = 'Checks whether too many enabled users hold a curated Tier-0 Entra ID role, directly or through a role-assignable group''s membership. Fails at 5 or more such users.'
    rationale   = 'A large population of standing Tier-0 role holders is a wide blast radius -- every one of those accounts is an equally attractive target for an attacker seeking full directory control, and a large population is harder to individually govern and review than a small, deliberately curated one.'
    severity    = 2
    category    = 'Users'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'DirectoryRoleAssignment', 'User', 'TransitiveMemberOf')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'User.Read.All'; confirmed = $true }
        @{ scope = 'Group.Read.All'; confirmed = $true }
        @{ scope = 'GroupMember.Read.All'; confirmed = $true }
    )

    applicability = 'A single tenant-scoped result. Always evaluated once the required evidence has been collected.'

    reasonCodes = @(
        @{ code = 'USR-006-EXCESSIVE-TIER-ZERO-USERS';    resultStatus = 'Fail';         description = '5 or more enabled users hold a curated Tier-0 Entra ID role, directly or through a role-assignable group.' }
        @{ code = 'USR-006-TIER-ZERO-USERS-WITHIN-RANGE'; resultStatus = 'Pass';        description = 'Fewer than 5 enabled users hold a curated Tier-0 Entra ID role.' }
        @{ code = 'USR-006-EVIDENCE-NOT-COLLECTED';       resultStatus = 'NotEvaluated'; description = 'DirectoryRole, DirectoryRoleAssignment, User, or TransitiveMemberOf evidence was not fully collected for this snapshot.' }
        @{ code = 'USR-006-EVALUATOR-ERROR';              resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Exactly one tenant-scoped result. Fail if 5 or more enabled users (counted once each, deduplicated across direct and group-derived membership) hold an Active assignment to a curated Tier-0 role; Pass otherwise. Only User principals are counted -- service principal and agent identity Tier-0 role holding are separate findings (ENT-006/009/011, AGT-004/008). NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureEntraLeastPrivilegeControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review the Tier-0 role holder population and remove standing access from users who do not need it; move remaining holders to PIM-eligible, time-bound assignments where possible (see PIM-001/002).'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/directoryrole-list-members?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic or its graduated multi-band confidence/severity scoring -- this project uses a single fixed threshold (5 users) and fixed severity, matching every other control in this project''s own registry. Reuses entirely pre-existing evidence (DirectoryRole/DirectoryRoleAssignment already established by PRIV-001/PIM-002, User by USR-007/008, TransitiveMemberOf by GRP-005) -- zero new collection.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'USR-006' }
    )

    baselineDependency = $null
}
