@{
    <#
        Fixed-state control (VNext build order item 8; per-role PIM activation-policy setting).
        Control ID/title continuity from 15-feature-parity-matrix.md section 3.3's
        EntraFalcon-derived canonical finding registry (PIM-004, "Tier-0 Roles Which Do Not
        Require Justification on Activation", severity 1) -- per docs/VNext.md's review-not-reuse
        policy, only that listing's title/severity/category was used; EntraFalcon's own check
        logic was not read. Keys are deliberately camelCase -- see XTA-001.psd1's header comment
        for why.
    #>
    controlId   = 'PIM-004'
    version     = '1.0.0'
    title       = 'Tier-0 Role Does Not Require Justification on Activation'
    description = "For each curated Tier-0 directory role, checks whether the role's PIM activation policy requires a business justification when an eligible user self-activates."
    rationale   = 'Microsoft''s own PIM role-settings documentation directly describes this setting: "Require justification on activation: You can require users to enter a business justification when they activate the eligible assignment." A recorded justification gives a reviewable, attributable reason for every Tier-0 activation, supporting after-the-fact audit and anomaly detection that an unexplained activation cannot.'
    severity    = 1
    category    = 'Privileged Roles'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'RoleManagementPolicyAssignment')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'RoleManagementPolicy.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per curated Tier-0 role (same set PIM-002/PIM-003 use) that has a corresponding RoleManagementPolicyAssignment in evidence. A single tenant-scoped NotApplicable result is returned if none of the curated roles were present as DirectoryRole entities at all.'

    reasonCodes = @(
        @{ code = 'PIM-004-JUSTIFICATION-NOT-REQUIRED'; resultStatus = 'Fail';         description = 'The role''s activation policy enabledRules does not contain "Justification".' }
        @{ code = 'PIM-004-JUSTIFICATION-REQUIRED';     resultStatus = 'Pass';        description = 'The role''s activation policy enabledRules contains "Justification".' }
        @{ code = 'PIM-004-NO-TIER-ZERO-ROLES-ACTIVATED'; resultStatus = 'NotApplicable'; description = 'None of the curated Tier-0 roles were present as DirectoryRole entities in the evidence set.' }
        @{ code = 'PIM-004-EVIDENCE-NOT-COLLECTED';     resultStatus = 'NotEvaluated'; description = 'DirectoryRole or RoleManagementPolicyAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'PIM-004-EVALUATOR-ERROR';            resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per curated Tier-0 role with a corresponding RoleManagementPolicyAssignment. Fail when the activation-policy enabledRules array does not contain "Justification". Pass when it does. A role with no corresponding RoleManagementPolicyAssignment entity is skipped (no result). NotApplicable (single tenant-scoped result) only if no curated Tier-0 role exists in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureTierZeroActivationJustificationControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Enable "Require justification on activation" in the role''s PIM role settings.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'
        'https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyenablementrule?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Control ID/title reused from 15-feature-parity-matrix.md section 3.3's EntraFalcon-derived canonical finding registry (PIM-004) for tracking continuity; check logic authored independently from Microsoft's own PIM role-settings documentation (re-fetched 2026-08-07), not read from or ported out of EntraFalcon's source, per docs/VNext.md's review-not-reuse policy."
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PIM-004' }
    )

    baselineDependency = $null
}
