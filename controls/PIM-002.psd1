@{
    <#
        Temporal/PIM control (Phase 7, fourth and final named tier: "fixed-state, relational,
        transitive, then temporal/PIM"): cross-references Active DirectoryRoleAssignment
        relationships against PimEligible relationships for the same principal/role pair, for a
        curated set of Tier-0 roles. Keys are deliberately camelCase -- see XTA-001.psd1's
        header comment for why.

        Control ID/title reused from 15-feature-parity-matrix.md section 3.3's canonical
        EntraFalcon-derived finding registry entry PIM-002 "Tier-0 Roles With Active Assignments
        Outside PIM" (severity 2) -- the matrix's own description matches this control's design
        closely (unlike GRP-005's narrower reuse), since both check the same underlying
        principal+role standing-vs-eligible correlation using evidence this project already
        collects (DirectoryRoleAssignment, PimEligible), with no additional evidence domain
        needed. Not verified against EntraFalcon's actual source logic for this pass -- treat as
        independently authored to the same named finding, not a byte-for-byte port.

        The Tier-0 role set below is a curated judgment call (documented in the description
        field), not sourced from a single pinned Microsoft citation -- flagged in
        00-open-questions.md's Phase 7 section for the same follow-up verification already
        tracked for PRIV-001's uncited "Microsoft's own guidance" claim.
    #>
    controlId   = 'PIM-002'
    version     = '1.0.0'
    title       = 'Tier-0 Roles With Active Assignments Outside PIM'
    description = 'For each Active DirectoryRoleAssignment targeting a curated Tier-0 role (Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator), checks whether the same principal also has a PimEligible relationship for that same role. A standing assignment with no corresponding eligibility record means the principal holds the role permanently, never having to activate it through PIM.'
    rationale   = 'PIM-eligible activation gives a Tier-0 role holder just-in-time, time-bounded, auditable access instead of always-on standing access -- a principal with a standing assignment and no PIM eligibility record for that role bypasses that control entirely, holding Tier-0 privilege continuously regardless of whether they are actively using it. This is the same over-provisioning/blast-radius concern PRIV-001 checks by count, examined here per-principal and cross-referenced against whether PIM governs the assignment at all.'
    severity    = 2
    category    = 'PIM'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'DirectoryRoleAssignment', 'PimEligible')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per Active DirectoryRoleAssignment targeting one of the curated Tier-0 roles that was present in evidence. NotApplicable (a single tenant-scoped result) if none of the curated Tier-0 roles were activated in the tenant (no matching DirectoryRole entities).'

    reasonCodes = @(
        @{ code = 'PIM-002-STANDING-ASSIGNMENT-OUTSIDE-PIM'; resultStatus = 'Fail';         description = 'The principal has an Active DirectoryRoleAssignment to a Tier-0 role with no corresponding PimEligible relationship for that role.' }
        @{ code = 'PIM-002-ASSIGNMENT-GOVERNED-BY-PIM';       resultStatus = 'Pass';        description = 'The principal has both an Active DirectoryRoleAssignment and a PimEligible relationship for the same Tier-0 role.' }
        @{ code = 'PIM-002-NO-TIER-ZERO-ROLES-ACTIVATED';     resultStatus = 'NotApplicable'; description = 'None of the curated Tier-0 roles (Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator) were present as DirectoryRole entities in the evidence set.' }
        @{ code = 'PIM-002-EVIDENCE-NOT-COLLECTED';           resultStatus = 'NotEvaluated'; description = 'DirectoryRole, DirectoryRoleAssignment, or PimEligible evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'PIM-002-EVALUATOR-ERROR';                  resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per Active DirectoryRoleAssignment targeting a curated Tier-0 role. Fail if no PimEligible relationship exists for the same principal and role. Pass if one does. NotApplicable (single tenant-scoped result) only if none of the curated Tier-0 roles exist in evidence at all. A Tier-0 role that exists but has zero Active assignments produces zero PIM-002 results for that role (nothing to check), not a Pass or Fail. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureStandingTierZeroAssignmentControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Convert the standing assignment to a PIM-eligible one: remove the Active DirectoryRoleAssignment and create a corresponding role-eligibility schedule, requiring the principal to activate the role through PIM (with justification, approval, and/or authentication context as configured) rather than holding it continuously.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure'
        'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3''s EntraFalcon-derived canonical finding registry (PIM-002, "Tier-0 Roles With Active Assignments Outside PIM"). Independently authored against this project''s own DirectoryRoleAssignment/PimEligible evidence contracts -- EntraFalcon''s actual EF-PIM-* source logic was not read for this pass. The Tier-0 role set is a curated judgment call, not independently re-verified this session -- see this file''s own header comment.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PIM-002' }
    )

    baselineDependency = $null
}
