@{
    <#
        Temporal control (VNext build order item 8; per-role PIM activation-policy setting, same
        category as PIM-002). Control ID/title continuity from
        15-feature-parity-matrix.md section 3.3's EntraFalcon-derived canonical finding registry
        (PIM-003, "Tier-0 Roles With Long Activation Duration (>4 Hours)", severity 1) -- per
        docs/VNext.md's review-not-reuse policy, only that listing's title/severity/category was
        used; EntraFalcon's own check logic was not read. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'PIM-003'
    version     = '1.0.0'
    title       = 'Tier-0 Role Activation Duration Exceeds 4 Hours'
    description = "For each curated Tier-0 directory role, checks the role's PIM activation policy for how long a self-activated assignment remains active before it expires (Microsoft's admin center calls this ""Activation maximum duration"", a 1-24 hour slider)."
    rationale   = "A shorter activation window bounds how long a compromised or misused activated session can act with Tier-0 privilege before it automatically expires, without meaningfully impairing legitimate work (an admin can simply reactivate). Microsoft's own documentation states the activation duration is configurable from 1 to 24 hours but does not itself recommend a specific number. This project's own threshold of 4 hours is a reasoned judgment call, not a Microsoft-quoted value -- a bounded, short-lived activation window is consistent with the standing-access-minimization theme Microsoft's broader PIM guidance repeats elsewhere (see PRIV-001's and GRP-005's own provenance notes for the same class of project-owned heuristic)."
    severity    = 1
    category    = 'Privileged Roles'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'RoleManagementPolicyAssignment')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'RoleManagementPolicy.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per curated Tier-0 role (Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator -- same set PIM-002 uses) that has a corresponding RoleManagementPolicyAssignment in evidence. A single tenant-scoped NotApplicable result is returned if none of the curated roles were present as DirectoryRole entities at all.'

    reasonCodes = @(
        @{ code = 'PIM-003-DURATION-EXCEEDS-THRESHOLD'; resultStatus = 'Fail';         description = 'The role''s activation maximumDuration exceeds 4 hours.' }
        @{ code = 'PIM-003-DURATION-WITHIN-THRESHOLD';  resultStatus = 'Pass';        description = 'The role''s activation maximumDuration is 4 hours or less.' }
        @{ code = 'PIM-003-NO-TIER-ZERO-ROLES-ACTIVATED'; resultStatus = 'NotApplicable'; description = 'None of the curated Tier-0 roles were present as DirectoryRole entities in the evidence set.' }
        @{ code = 'PIM-003-EVIDENCE-NOT-COLLECTED';     resultStatus = 'NotEvaluated'; description = 'DirectoryRole or RoleManagementPolicyAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'PIM-003-EVALUATOR-ERROR';            resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per curated Tier-0 role with a corresponding RoleManagementPolicyAssignment. Fail when maximumDuration (ISO 8601 duration) parses to more than 4 hours. Pass when 4 hours or less. A role with no corresponding RoleManagementPolicyAssignment entity, or no parseable maximumDuration, is skipped (no result), not reported Fail. NotApplicable (single tenant-scoped result) only if no curated Tier-0 role exists in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureTierZeroActivationDurationControl'
    evidenceRedactionPolicy = 'None'

    remediation = "Lower the role's ""Activation maximum duration"" setting in PIM role settings to 4 hours or less."

    references = @(
        'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'
        'https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyexpirationrule?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Control ID/title reused from 15-feature-parity-matrix.md section 3.3's EntraFalcon-derived canonical finding registry (PIM-003) for tracking continuity; check logic authored independently from Microsoft's own PIM role-settings documentation (re-fetched 2026-08-07), not read from or ported out of EntraFalcon's source, per docs/VNext.md's review-not-reuse policy. The 4-hour threshold is this project's own judgment call (see this control's own rationale), not independently re-derived from EntraFalcon -- it happens to match the finding's own name, which is the only thing about this specific number this project actually looked at."
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PIM-003' }
    )

    baselineDependency = $null
}
