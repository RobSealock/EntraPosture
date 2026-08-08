@{
    <#
        Fixed-state control (VNext build order item 8; per-role PIM activation-policy setting).
        Control ID/title continuity from 15-feature-parity-matrix.md section 3.3's
        EntraFalcon-derived canonical finding registry (PIM-009, "Tier-0 Roles Without
        Authentication Context or Approval", severity 2) -- per docs/VNext.md's review-not-reuse
        policy, only that listing's title/severity/category was used; EntraFalcon's own check
        logic was not read. Keys are deliberately camelCase -- see XTA-001.psd1's header comment
        for why.

        This is the control 15-feature-parity-matrix.md section 10 names as the reason
        AUTHCTX-001/002 (build order item 7) exist at all: this control only checks that
        authentication context or approval is *configured*, it has no way to detect a
        configured-but-non-functional authentication context (see AUTHCTX-001/002's own
        provenance notes) -- that correctness gap is intentionally out of scope for this control
        and closed by that pair instead.
    #>
    controlId   = 'PIM-009'
    version     = '1.0.0'
    title       = 'Tier-0 Role Requires Neither Authentication Context Nor Approval on Activation'
    description = "For each curated Tier-0 directory role, checks whether the role's PIM activation policy requires at least one of: a Conditional Access authentication context, or approval -- either satisfies this control; neither being configured is the failure condition."
    rationale   = "Microsoft's own PIM role-settings documentation directly describes both mechanisms as additional activation-time barriers beyond standard multifactor authentication: authentication context lets an admin require a stronger, distinct authentication event (e.g. a specific authentication strength, or an Intune-compliant device) at activation time; approval requires a separate human decision before activation succeeds at all. A Tier-0 role requiring neither has only whatever baseline PIM-004/PIM-003 already enforce (justification, a bounded duration) standing between an eligible principal and activation -- this control checks for the presence of an additional, deliberate barrier beyond that baseline, matching the 'or' framing in the finding's own name: either mechanism is sufficient, this control does not require both."
    severity    = 2
    category    = 'Privileged Roles'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'RoleManagementPolicyAssignment')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'RoleManagementPolicy.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per curated Tier-0 role (same set PIM-002 through PIM-008 use) that has a corresponding RoleManagementPolicyAssignment in evidence. A single tenant-scoped NotApplicable result is returned if none of the curated roles were present as DirectoryRole entities at all.'

    reasonCodes = @(
        @{ code = 'PIM-009-NEITHER-CONFIGURED';       resultStatus = 'Fail';         description = 'Neither authenticationContextEnabled nor approvalRequired is true for this role''s activation policy.' }
        @{ code = 'PIM-009-AT-LEAST-ONE-CONFIGURED';  resultStatus = 'Pass';        description = 'authenticationContextEnabled and/or approvalRequired is true for this role''s activation policy.' }
        @{ code = 'PIM-009-NO-TIER-ZERO-ROLES-ACTIVATED'; resultStatus = 'NotApplicable'; description = 'None of the curated Tier-0 roles were present as DirectoryRole entities in the evidence set.' }
        @{ code = 'PIM-009-EVIDENCE-NOT-COLLECTED';   resultStatus = 'NotEvaluated'; description = 'DirectoryRole or RoleManagementPolicyAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'PIM-009-EVALUATOR-ERROR';          resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per curated Tier-0 role with a corresponding RoleManagementPolicyAssignment. Fail only when both authenticationContextEnabled is false (or absent) and approvalRequired is false (or absent). Pass when at least one is true -- this control does not distinguish which one, or judge whether a configured authentication context is actually functional (that is AUTHCTX-001/002''s job). A role with no corresponding RoleManagementPolicyAssignment entity is skipped (no result). NotApplicable (single tenant-scoped result) only if no curated Tier-0 role exists in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureTierZeroAuthContextOrApprovalControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Configure either a Conditional Access authentication context (ensuring the referencing policy is enabled, enforcing, and covers the role''s full assignee population -- see AUTHCTX-001/002) or require approval to activate, in the role''s PIM role settings.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'
        'https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyapprovalrule?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyauthenticationcontextrule?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Control ID/title reused from 15-feature-parity-matrix.md section 3.3's EntraFalcon-derived canonical finding registry (PIM-009) for tracking continuity; check logic authored independently from Microsoft's own PIM role-settings documentation (re-fetched 2026-08-07), not read from or ported out of EntraFalcon's source, per docs/VNext.md's review-not-reuse policy. Deliberately does not attempt to judge authentication-context functional effectiveness -- that gap is closed by AUTHCTX-001/002 (build order item 7), built specifically to cover this control's own documented blind spot, not duplicated here."
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PIM-009' }
    )

    baselineDependency = $null
}
