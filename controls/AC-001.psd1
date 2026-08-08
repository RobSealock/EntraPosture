@{
    <#
        Fixed-state predicate control (Phase 7, first of the phase's dependency-ordered tiers:
        "fixed-state, relational, transitive, then temporal/PIM"): evaluates a single
        AuthorizationPolicy entity's permissionGrantPoliciesAssigned field. Keys are
        deliberately camelCase, matching control-definition.schema.json exactly -- see
        controls/XTA-001.psd1's header comment for why.

        Simplified from 15-feature-parity-matrix.md section 9's full AC-001 design: that design
        also checks authorizationPolicy.allowUserConsentForRiskyApps independently of the
        permission-grant-policy dimension, and resolves custom (non-built-in) permission grant
        policy IDs to their actual conditions via a separate /policies/permissionGrantPolicies
        read. Neither allowUserConsentForRiskyApps nor permissionGrantPolicies is in this
        project's current AuthorizationPolicy evidence field allowlist (src/Normalization/
        NormalizeTenantPolicies.ps1) -- collecting them is real, separately-scopable follow-up
        work, not done in this pass. This control checks only whether a *built-in* legacy policy
        ID is assigned; a custom policy ID of equivalent breadth is not detected. Documented as a
        known, deliberate v1 boundary in 00-open-questions.md's Phase 7 section, not silently
        assumed complete.
    #>
    controlId   = 'AC-001'
    version     = '1.0.0'
    title       = 'Default User Consent Policy Assigns the Legacy (Broad) Permission Grant Policy'
    description = "Checks the tenant's authorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned for the built-in 'microsoft-user-default-legacy' policy, which allows any user to consent to any non-admin-required permission for any application, rather than the narrower 'microsoft-user-default-low' policy scoped to verified publishers and low-impact permissions."
    rationale   = "The legacy policy is the broadest built-in consent surface Microsoft ships: any user can grant any non-admin-required permission to any application, verified or not. This is the exact 'unverified app tricks a user into granting broad data access' pattern Microsoft's own guidance names as the reason to prefer the narrow policy -- and unlike most settings this project checks, the difference between the two built-in policies is a single field value, making this a fixed-state, single-object check."
    severity    = 3
    category    = 'App Consent'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AuthorizationPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable when the tenant''s authorizationPolicy was collected -- every tenant has exactly one.'

    reasonCodes = @(
        @{ code = 'AC-001-LEGACY-POLICY-ASSIGNED';    resultStatus = 'Fail';         description = 'permissionGrantPoliciesAssigned includes a policy ID ending in ''.microsoft-user-default-legacy''.' }
        @{ code = 'AC-001-RESTRICTED-POLICY-ASSIGNED'; resultStatus = 'Pass';        description = 'permissionGrantPoliciesAssigned does not include the legacy built-in policy ID (built-in ''microsoft-user-default-low'', a custom policy, or an empty/unset assignment).' }
        @{ code = 'AC-001-NO-POLICY-FOUND';            resultStatus = 'NotApplicable'; description = 'No AuthorizationPolicy entity was present in the evidence set (unexpected in a real tenant, but handled defensively).' }
        @{ code = 'AC-001-EVIDENCE-NOT-COLLECTED';     resultStatus = 'NotEvaluated'; description = 'AuthorizationPolicy evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AC-001-EVALUATOR-ERROR';            resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Fail when permissionGrantPoliciesAssigned contains an entry ending in ''.microsoft-user-default-legacy''. Pass otherwise (including when the array is empty, which Microsoft documents as falling back to no user consent at all -- strictly narrower than legacy, not a finding). NotApplicable only if no AuthorizationPolicy entity exists in evidence at all. NotEvaluated/Error are never produced by the evaluator function itself -- assigned by the orchestration layer (engineering plan section 9.2).'

    evaluatorFunctionName  = 'Test-EntraPostureDefaultUserConsentPolicyControl'
    evidenceRedactionPolicy = 'None'

    remediation = "Assign 'microsoft-user-default-low' (or an equivalently narrow custom policy, verified by reading its actual conditions rather than trusting its name) to defaultUserRolePermissions.permissionGrantPoliciesAssigned. Classify permissions as low-impact deliberately rather than leaving the classification unset."

    references = @(
        'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent'
        'https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Clean-room control authored directly from Microsoft Learn app-consent guidance and 15-feature-parity-matrix.md section 9's AC-001 design (itself flagged there as refining EntraFalcon's USR-004 for this specific dimension, not ported from EntraFalcon source). References not independently re-fetched/re-verified as live URLs during this Phase 7 authoring session -- flagged in 00-open-questions.md for the same follow-up citation-verification pass already tracked for Phase 5's controls."
    }

    externalMappings = @()

    baselineDependency = @{
        documentationUrl  = 'https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0'
        asOfDate          = '2026-03-04'
        citationStrength  = 'ApiExampleResponse'
    }
}
