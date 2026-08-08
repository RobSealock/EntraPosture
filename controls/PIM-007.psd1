@{
    <#
        Fixed-state control (VNext build order item 8; per-role PIM direct/permanent assignment
        policy setting). Control ID/title continuity from 15-feature-parity-matrix.md section
        3.3's EntraFalcon-derived canonical finding registry (PIM-007, "Tier-0 Roles Without MFA
        on Active Assignments", severity 1) -- per docs/VNext.md's review-not-reuse policy, only
        that listing's title/severity/category was used; EntraFalcon's own check logic was not
        read. Keys are deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'PIM-007'
    version     = '1.0.0'
    title       = 'Tier-0 Role Does Not Require MFA on Direct Active Assignment'
    description = "For each curated Tier-0 directory role, checks whether the role's PIM policy requires the assigning admin to satisfy multifactor authentication when creating a direct active assignment."
    rationale   = 'Microsoft''s own PIM role-settings documentation directly describes this setting, and its own real limitation: "Require multifactor authentication on active assignment: You can require that administrators provide multifactor authentication when they create an active (as opposed to eligible) assignment. Privileged Identity Management can''t enforce multifactor authentication when the user uses their role assignment because they''re already active in the role from the time that it''s assigned." Requiring MFA at assignment time is the only point in a direct-assignment workflow PIM can actually gate -- once assigned, the grant is already live.'
    severity    = 1
    category    = 'Privileged Roles'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'RoleManagementPolicyAssignment')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'RoleManagementPolicy.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per curated Tier-0 role (same set PIM-002/003/004/005/006 use) that has a corresponding RoleManagementPolicyAssignment in evidence. A single tenant-scoped NotApplicable result is returned if none of the curated roles were present as DirectoryRole entities at all.'

    reasonCodes = @(
        @{ code = 'PIM-007-MFA-NOT-REQUIRED'; resultStatus = 'Fail';         description = 'The role''s Admin/Assignment-level enablement rule enabledRules does not contain "MultiFactorAuthentication".' }
        @{ code = 'PIM-007-MFA-REQUIRED';     resultStatus = 'Pass';        description = 'The role''s Admin/Assignment-level enablement rule enabledRules contains "MultiFactorAuthentication".' }
        @{ code = 'PIM-007-NO-TIER-ZERO-ROLES-ACTIVATED'; resultStatus = 'NotApplicable'; description = 'None of the curated Tier-0 roles were present as DirectoryRole entities in the evidence set.' }
        @{ code = 'PIM-007-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'DirectoryRole or RoleManagementPolicyAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'PIM-007-EVALUATOR-ERROR';  resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per curated Tier-0 role with a corresponding RoleManagementPolicyAssignment. Fail when adminAssignmentEnabledRules does not contain "MultiFactorAuthentication". Pass when it does. A role with no corresponding RoleManagementPolicyAssignment entity is skipped (no result). NotApplicable (single tenant-scoped result) only if no curated Tier-0 role exists in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureTierZeroAssignmentMfaControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Enable "Require multifactor authentication on active assignment" in the role''s PIM role settings.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'
        'https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyenablementrule?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Control ID/title reused from 15-feature-parity-matrix.md section 3.3's EntraFalcon-derived canonical finding registry (PIM-007) for tracking continuity; check logic authored independently from Microsoft's own PIM role-settings documentation (re-fetched 2026-08-07), not read from or ported out of EntraFalcon's source, per docs/VNext.md's review-not-reuse policy."
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PIM-007' }
    )

    baselineDependency = $null
}
