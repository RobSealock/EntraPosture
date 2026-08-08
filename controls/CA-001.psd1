@{
    <#
        Gap-analysis control (Phase 8, the bounded representative-scenario tier -- explicitly
        NOT the full caOptics/CA-Insight combinatorial permutation approach, which would generate
        every dimension combination rather than a small fixed representative set; see this
        project's own scope-boundary note in 00-open-questions.md's Phase 8 section for why a
        full bulk-permutation engine was not attempted this pass). Keys are deliberately
        camelCase -- see XTA-001.psd1's header comment for why.

        Evaluates the Global Administrator role (the same single-role narrowing precedent
        PRIV-001 already established, rather than the full curated Tier-0 set PIM-002 uses) across
        16 fixed representative scenarios (4 platforms x 4 client app types), using Phase 8's
        deterministic CA simulation engine
        (src/ConditionalAccess/EvaluateScenario.ps1, cited semantics in
        16-ca-evaluation-semantics.md). This is a genuine multi-dimension coverage check -- not a
        single scenario -- while staying bounded and explainable, matching the engineering plan's
        explicit "controls combinatorial explosion... never hide sampling" requirement: all 16
        scenarios are always evaluated and reported, never sampled down.
    #>
    controlId   = 'CA-001'
    version     = '1.0.0'
    title       = 'Global Administrator Sign-In Not Universally Protected by MFA'
    description = "Evaluates 16 representative sign-in scenarios (4 platforms x 4 client app types) for a principal holding the Global Administrator role against every collected Conditional Access policy, using this project's deterministic simulation engine. Fails per scenario where no applicable, enabled policy either blocks the sign-in or requires MFA."
    rationale   = "Requiring MFA for administrative roles is Microsoft's own most consistently repeated Conditional Access baseline recommendation. A single policy covering the common case (browser, Windows) can still leave a real gap for a legacy-auth client type or an unmanaged mobile platform that the policy's own conditions don't reach -- exactly the 'no policy matched' failure mode Conditional Access's per-policy, per-condition model makes easy to introduce without a deliberate decision. Checking a fixed representative grid instead of a single scenario is this project's bounded, explainable, non-sampled alternative to full combinatorial coverage analysis."
    severity    = 4
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'ConditionalAccessPolicy')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once (16 scenario results) when the Global Administrator DirectoryRole entity was present in the evidence set. NotApplicable if it was never activated in the tenant.'

    reasonCodes = @(
        @{ code = 'CA-001-UNCOVERED-SCENARIO';          resultStatus = 'Fail';         description = 'For this platform/client-app-type combination, no applicable enabled Conditional Access policy blocks the sign-in or requires the mfa control.' }
        @{ code = 'CA-001-SCENARIO-COVERED';             resultStatus = 'Pass';         description = 'For this platform/client-app-type combination, at least one applicable enabled policy blocks the sign-in or requires the mfa control.' }
        @{ code = 'CA-001-NO-GA-ROLE-ACTIVATED';         resultStatus = 'NotApplicable'; description = 'No Global Administrator DirectoryRole entity was present in the evidence set.' }
        @{ code = 'CA-001-EVIDENCE-NOT-COLLECTED';       resultStatus = 'NotEvaluated'; description = 'DirectoryRole or ConditionalAccessPolicy evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'CA-001-EVALUATOR-ERROR';              resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per representative scenario (16 per assessment) when the Global Administrator role exists in evidence. Fail per scenario where the simulation engine''s Result is not Blocked and no RequiredControlGroups entry includes the mfa control. Pass otherwise. NotApplicable (a single tenant-scoped result, not 16) only if the Global Administrator role was never activated. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureConditionalAccessAdminCoverageControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Create or extend a Conditional Access policy targeting the Global Administrator role (or All users, if intentionally broad) that requires MFA, with an Applications/client app types/platforms scope broad enough to cover every legitimate sign-in surface -- explicitly including legacy authentication clients and every managed device platform in use, not just the primary browser/Windows case.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies'
        'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Clean-room control built on Phase 8''s own simulation engine (src/ConditionalAccess/EvaluateScenario.ps1), not ported from Conditional Access Validator, caOptics, or CA Insight -- those informed the review plan''s WS4 design discussion (16-ca-evaluation-semantics.md), not this control''s specific implementation. References not independently re-fetched/re-verified as live URLs during this Phase 8 authoring session beyond the direct quotes already captured in 16-ca-evaluation-semantics.md.'
    }

    externalMappings = @()

    baselineDependency = $null
}
