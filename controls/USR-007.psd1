@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08, batch
        4). Keys deliberately camelCase.
    #>
    controlId   = 'USR-007'
    version     = '1.0.0'
    title       = 'Hybrid Users with Tier-0 Entra ID Roles'
    description = 'For each hybrid-synced User entity (onPremisesSyncEnabled=true), checks whether it holds an Active DirectoryRoleAssignment to a curated Tier-0 role.'
    rationale   = 'An on-premises Active Directory compromise is a materially larger, harder-to-fully-secure attack surface than cloud-only Entra ID identity -- a hybrid-synced account holding cloud Tier-0 privilege means an on-prem breach can reach the highest tier of cloud control, the specific risk Microsoft''s own hybrid-identity security guidance names directly (recommending cloud-only accounts for Tier-0 administration).'
    severity    = 2
    category    = 'Identity'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('User', 'DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'User.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per User entity with onPremisesSyncEnabled=true. NotApplicable (a single tenant-scoped result) if the tenant has no hybrid-synced users at all.'

    reasonCodes = @(
        @{ code = 'USR-007-HYBRID-TIER-ZERO-ROLE';  resultStatus = 'Fail';         description = 'The hybrid-synced user holds an Active assignment to a curated Tier-0 role.' }
        @{ code = 'USR-007-NO-TIER-ZERO-ROLE';      resultStatus = 'Pass';        description = 'The hybrid-synced user holds no Active assignment to any curated Tier-0 role.' }
        @{ code = 'USR-007-NO-HYBRID-USERS';        resultStatus = 'NotApplicable'; description = 'No User entity with onPremisesSyncEnabled=true was present in the evidence set.' }
        @{ code = 'USR-007-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'User, DirectoryRole, or DirectoryRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'USR-007-EVALUATOR-ERROR';        resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per hybrid-synced User entity. Fail if an Active DirectoryRoleAssignment to a curated Tier-0 role exists for it, Pass otherwise. NotApplicable (single tenant-scoped result) only if zero hybrid-synced users exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureHybridUserEntraRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Provision a dedicated cloud-only account for Tier-0 administration and remove the Tier-0 assignment from the hybrid-synced account, per Microsoft''s own recommended guidance.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. onPremisesSyncEnabled requires an explicit $select on GET /v1.0/users -- confirmed live against the "List users" Graph reference page, re-fetched 2026-08-08; this also caught and fixed a pre-existing bug where this collector''s other allowlisted fields (accountEnabled, userType) were never actually requested either.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'USR-007' }
    )

    baselineDependency = $null
}
