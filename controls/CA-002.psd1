@{
    <#
        Gap-analysis control (v.next build order item 12) -- the full caOptics/CA-Insight-style
        combinatorial permutation approach CA-001.psd1's own header comment named as explicitly
        NOT attempted in Phase 8. Keys are deliberately camelCase -- see XTA-001.psd1's header
        comment for why.

        Generalizes CA-001 two ways: every curated Tier-0 role (not just Global Administrator),
        and a scenario set generated deterministically from this tenant's own collected policies
        (platform, clientAppType, location-trust, signInRiskLevel, userRiskLevel), not a hardcoded
        constant grid -- see Get-EntraPostureConditionalAccessCombinatorialScenario's own
        DESCRIPTION for the full policy-induced-equivalence-partitioning design, reviewed against
        caOptics'/CA Insight's own published algorithm descriptions (design/approach only, per
        docs/VNext.md's review-not-reuse policy -- no source from either project was read) before
        being designed independently. Bounded by -MaxScenarios (default 5000, throws rather than
        silently truncating) -- the engineering plan's explicit "never hide sampling" requirement
        (section 9.4) applies here exactly as it does to CA-001's fixed 16-scenario grid.

        Deliberately does NOT expand real per-object dimensions this item was scoped to leave out
        (real NamedLocation IDs instead of the fixed trusted/untrusted pair, per-application
        expansion instead of the fixed 'All' representative, and full user/group
        equivalence-class derivation instead of the curated Tier-0 role set) -- each a real,
        separately-scopable amount of work, not silently narrowed without saying so. See
        00-open-questions.md item 30 for the full writeup, including the CA-001 "strong control"
        definition gap this item's own broader definition surfaced but deliberately does not fix
        in CA-001 itself.
    #>
    controlId   = 'CA-002'
    version     = '1.0.0'
    title       = 'Curated Tier-0 Roles Not Universally Protected Across the Full Modeled Condition-Dimension Space'
    description = "Evaluates a deterministically-generated, policy-induced combinatorial scenario set (platform x clientAppType x location-trust x signInRiskLevel x userRiskLevel) for every curated Tier-0 role against every collected Conditional Access policy, using this project's deterministic simulation engine. Fails per scenario where no applicable, enabled policy either blocks the sign-in or requires MFA (directly or via a satisfying authentication strength)."
    rationale   = "CA-001's fixed 16-scenario grid checks one role across two dimensions; a policy authored around the common case can still leave a gap on a risk level, location-trust state, or platform/client-app-type combination nobody enumerated by hand. Generating the scenario set from what this tenant's own policies actually distinguish by -- rather than a hand-picked constant grid -- is this project's bounded, explainable, non-sampled approximation of the full caOptics/CA-Insight combinatorial coverage-gap analysis the engineering plan names as a v.next capability."
    severity    = 4
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'ConditionalAccessPolicy', 'AuthenticationStrengthPolicy')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'Policy.Read.All'; confirmed = $true }
        @{ scope = 'Policy.Read.AuthenticationMethod'; confirmed = $true }
    )

    applicability = 'Evaluated once per (curated Tier-0 role, generated scenario) pair when at least one curated Tier-0 DirectoryRole entity was present in the evidence set. A single tenant-scoped NotApplicable result is produced if none were.'

    reasonCodes = @(
        @{ code = 'CA-002-UNCOVERED-SCENARIO';           resultStatus = 'Fail';         description = 'For this generated scenario, no applicable enabled Conditional Access policy blocks the sign-in, requires the mfa control, or requires an authentication strength whose requirementsSatisfied is mfa.' }
        @{ code = 'CA-002-SCENARIO-COVERED';              resultStatus = 'Pass';         description = 'For this generated scenario, at least one applicable enabled policy blocks the sign-in or requires MFA (directly or via a satisfying authentication strength).' }
        @{ code = 'CA-002-NO-TIER-ZERO-ROLE-ACTIVATED';   resultStatus = 'NotApplicable'; description = 'No curated Tier-0 DirectoryRole entity was present in the evidence set.' }
        @{ code = 'CA-002-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'DirectoryRole or ConditionalAccessPolicy evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'CA-002-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence, including the case-generator exceeding its -MaxScenarios safety bound.' }
    )

    expectedResultSemantics = 'One result per (curated Tier-0 role, generated scenario) pair when at least one curated Tier-0 role exists in evidence -- the exact count varies by tenant (bounded by this tenant''s own Conditional Access policy complexity, not a fixed constant like CA-001''s 16). Fail per scenario where the simulation engine''s Result is not Blocked, no RequiredControlGroups entry includes the mfa control, and no RequiredControlGroups entry''s AuthenticationStrengthId resolves to an authentication strength whose requirementsSatisfied is mfa. Pass otherwise. A single tenant-scoped NotApplicable result is produced instead if no curated Tier-0 role was ever activated. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself, except that the case-generator throwing (its -MaxScenarios bound exceeded) surfaces as CA-002-EVALUATOR-ERROR the same way any other evaluator exception would.'

    evaluatorFunctionName  = 'Test-EntraPostureConditionalAccessCombinatorialCoverageControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Extend Conditional Access coverage for curated Tier-0 roles to every platform, client app type, location-trust state, and risk level this control''s generated scenario set found uncovered -- particularly legacy-auth client types, unmanaged/less-common platforms, and any risk-level condition a policy''s own authors did not anticipate needing separate coverage for.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies'
        'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning'
        'https://github.com/jsa2/caOptics'
        'https://github.com/emiliensocchi/entra-ca-insight'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Clean-room control and case-generation algorithm, built on Phase 8's own simulation engine (src/ConditionalAccess/EvaluateScenario.ps1) and this project's own independently-designed policy-induced equivalence-partitioning approach -- not ported from caOptics or CA Insight. Per docs/VNext.md's review-not-reuse policy: only each project's published README-level algorithm description was reviewed (for design comparison), not their source code. The two caOptics/CA-Insight references above are cited for that design-comparison lineage, not as a source of implementation logic."
    }

    externalMappings = @()

    baselineDependency = $null
}
