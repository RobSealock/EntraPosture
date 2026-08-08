@{
    <#
        Fixed-state predicate control (Phase 7). Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.

        Simplified from 15-feature-parity-matrix.md section 9's full AC-002 design, which is
        classified there as Relational: it also cross-references the workflow's designated
        reviewers against known privileged-role evidence, to confirm at least one reviewer can
        actually approve Microsoft Graph application-permission consent (documented as requiring
        Global Administrator specifically). This project's AdminConsentRequestPolicy evidence
        deliberately stores only reviewerCount, not reviewer identities (see src/Normalization/
        NormalizeTenantPolicies.ps1's own docstring: "avoiding persisting a list of specific
        admin identities here") -- a privacy-minimization choice made in Phase 6 before this
        control's design was read closely. That choice makes the reviewer-capability
        cross-reference impossible with current evidence, so this control checks only enablement
        and reviewer presence (a fixed-state check on AdminConsentRequestPolicy alone), not
        reviewer capability. Documented as a known, deliberate v1 boundary in
        00-open-questions.md's Phase 7 section.
    #>
    controlId   = 'AC-002'
    version     = '1.0.0'
    title       = 'Admin Consent Workflow Not Enabled or Has No Reviewers Configured'
    description = "Checks the tenant's adminConsentRequestPolicy.isEnabled and reviewer count: the workflow is disabled, or enabled with zero reviewers configured, either of which means a user who cannot self-consent to an application has no path to request review."
    rationale   = "Microsoft's own documentation states that assignment-required applications always need admin consent no matter how the user consent policy is set -- so a nonfunctional admin consent workflow is a real gap even in a tenant whose default consent policy (AC-001) is already restrictive. A disabled or reviewer-less workflow gives users no real path and predictably leads to admins loosening the user consent policy instead to make the friction go away, undermining that control's protection through a different door."
    severity    = 2
    category    = 'App Consent'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AdminConsentRequestPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable when the tenant''s adminConsentRequestPolicy was collected -- the object exists as a single per-tenant policy regardless of whether it has been configured.'

    reasonCodes = @(
        @{ code = 'AC-002-WORKFLOW-DISABLED';          resultStatus = 'Fail';         description = 'isEnabled is false.' }
        @{ code = 'AC-002-NO-REVIEWERS-CONFIGURED';     resultStatus = 'Fail';         description = 'isEnabled is true but reviewerCount is 0.' }
        @{ code = 'AC-002-WORKFLOW-CONFIGURED';         resultStatus = 'Pass';         description = 'isEnabled is true and reviewerCount is at least 1.' }
        @{ code = 'AC-002-NO-POLICY-FOUND';             resultStatus = 'NotApplicable'; description = 'No AdminConsentRequestPolicy entity was present in the evidence set (unexpected in a real tenant, but handled defensively).' }
        @{ code = 'AC-002-EVIDENCE-NOT-COLLECTED';      resultStatus = 'NotEvaluated'; description = 'AdminConsentRequestPolicy evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AC-002-EVALUATOR-ERROR';             resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Fail (disabled) when isEnabled is false. Fail (no reviewers) when isEnabled is true and reviewerCount is 0. Pass when isEnabled is true and reviewerCount is at least 1. NotApplicable only if no AdminConsentRequestPolicy entity exists in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureAdminConsentWorkflowControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Enable the admin consent workflow (policies/adminConsentRequestPolicy.isEnabled) and assign at least one reviewer. Confirm the assigned reviewer(s) hold sufficient privilege to act on the consent requests this tenant actually receives -- Microsoft documents Global Administrator as required specifically for Microsoft Graph application-permission requests.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow'
        'https://learn.microsoft.com/en-us/graph/api/adminconsentrequestpolicy-get?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Clean-room control authored directly from Microsoft Learn admin-consent-workflow guidance and 15-feature-parity-matrix.md section 9's AC-002 design, narrowed to the fixed-state subset this project's already-collected evidence supports (see this file's own comment above for why the reviewer-capability cross-reference was descoped). References not independently re-fetched/re-verified as live URLs during this Phase 7 authoring session."
    }

    externalMappings = @()

    baselineDependency = @{
        documentationUrl  = 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow'
        asOfDate          = '2026-02-19'
        citationStrength  = 'Inference'
    }
}
