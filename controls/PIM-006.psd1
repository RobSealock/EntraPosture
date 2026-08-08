@{
    <#
        Fixed-state control (VNext build order item 8; per-role PIM direct/permanent assignment
        policy setting -- distinct from PIM-004's activation-justification setting, see this
        control's own rationale). Control ID/title continuity from
        15-feature-parity-matrix.md section 3.3's EntraFalcon-derived canonical finding registry
        (PIM-006, "Tier-0 Roles Without Justification on Active Assignments", severity 1) -- per
        docs/VNext.md's review-not-reuse policy, only that listing's title/severity/category was
        used; EntraFalcon's own check logic was not read. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'PIM-006'
    version     = '1.0.0'
    title       = 'Tier-0 Role Does Not Require Justification on Direct Active Assignment'
    description = "For each curated Tier-0 directory role, checks whether the role's PIM policy requires a business justification when an admin creates a direct active assignment -- distinct from PIM-004's check, which covers an eligible user's own self-activation justification, not an admin's direct-assignment action."
    rationale   = 'Microsoft''s own PIM role-settings documentation directly describes this setting: "Require justification on active assignment: You can require that users enter a business justification when they create an active (as opposed to eligible) assignment." A direct active assignment bypasses the eligible-activation workflow entirely (see PIM-005), so a recorded justification at assignment time is the only reviewable record of why that specific grant exists at all.'
    severity    = 1
    category    = 'Privileged Roles'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'RoleManagementPolicyAssignment')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'RoleManagementPolicy.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per curated Tier-0 role (same set PIM-002/003/004/005 use) that has a corresponding RoleManagementPolicyAssignment in evidence. A single tenant-scoped NotApplicable result is returned if none of the curated roles were present as DirectoryRole entities at all.'

    reasonCodes = @(
        @{ code = 'PIM-006-JUSTIFICATION-NOT-REQUIRED'; resultStatus = 'Fail';         description = 'The role''s Admin/Assignment-level enablement rule enabledRules does not contain "Justification".' }
        @{ code = 'PIM-006-JUSTIFICATION-REQUIRED';     resultStatus = 'Pass';        description = 'The role''s Admin/Assignment-level enablement rule enabledRules contains "Justification".' }
        @{ code = 'PIM-006-NO-TIER-ZERO-ROLES-ACTIVATED'; resultStatus = 'NotApplicable'; description = 'None of the curated Tier-0 roles were present as DirectoryRole entities in the evidence set.' }
        @{ code = 'PIM-006-EVIDENCE-NOT-COLLECTED';     resultStatus = 'NotEvaluated'; description = 'DirectoryRole or RoleManagementPolicyAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'PIM-006-EVALUATOR-ERROR';            resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per curated Tier-0 role with a corresponding RoleManagementPolicyAssignment. Fail when adminAssignmentEnabledRules does not contain "Justification". Pass when it does. A role with no corresponding RoleManagementPolicyAssignment entity is skipped (no result). NotApplicable (single tenant-scoped result) only if no curated Tier-0 role exists in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureTierZeroAssignmentJustificationControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Enable "Require justification on active assignment" in the role''s PIM role settings.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'
        'https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyenablementrule?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Control ID/title reused from 15-feature-parity-matrix.md section 3.3's EntraFalcon-derived canonical finding registry (PIM-006) for tracking continuity; check logic authored independently from Microsoft's own PIM role-settings documentation (re-fetched 2026-08-07), not read from or ported out of EntraFalcon's source, per docs/VNext.md's review-not-reuse policy."
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PIM-006' }
    )

    baselineDependency = $null
}
