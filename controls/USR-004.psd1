@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Keys
        deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'USR-004'
    version     = '1.0.0'
    title       = 'Users Are Allowed to Consent to Apps'
    description = 'Checks the tenant''s AuthorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned setting for the deprecated, unrestricted "microsoft-user-default-legacy" built-in consent policy, or an unrecognized custom policy.'
    rationale   = 'Under an unrestricted or unverified consent policy, any user can grant a malicious or over-privileged third-party application access to their own data (and, depending on the requested scope, more) without any admin review.'
    severity    = 2
    category    = 'Users'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AuthorizationPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per AuthorizationPolicy entity (in practice, exactly one). NotApplicable (a single tenant-scoped result) if the singleton is missing from evidence entirely.'

    reasonCodes = @(
        @{ code = 'USR-004-LEGACY-CONSENT-POLICY';      resultStatus = 'Fail';         description = 'Users may consent to apps under the deprecated, unrestricted "microsoft-user-default-legacy" built-in policy.' }
        @{ code = 'USR-004-CUSTOM-CONSENT-POLICY';      resultStatus = 'Fail';         description = 'Users may consent to apps under at least one custom app consent policy of unverifiable scope.' }
        @{ code = 'USR-004-RESTRICTED-CONSENT-POLICY';  resultStatus = 'Pass';        description = 'Users may consent to apps only under Microsoft''s own restrictive built-in policy (verified-publisher/low-risk permissions).' }
        @{ code = 'USR-004-CONSENT-DISABLED';           resultStatus = 'Pass';        description = 'User consent to apps is disabled entirely.' }
        @{ code = 'USR-004-NO-POLICY-FOUND';            resultStatus = 'NotApplicable'; description = 'No AuthorizationPolicy entity was present in the evidence set.' }
        @{ code = 'USR-004-EVIDENCE-NOT-COLLECTED';     resultStatus = 'NotEvaluated'; description = 'AuthorizationPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'USR-004-EVALUATOR-ERROR';            resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AuthorizationPolicy entity (in practice exactly one). Pass if permissionGrantPoliciesAssigned is empty (consent disabled) or contains only Microsoft''s own "recommended"/"low" built-in policies; Fail if it contains the deprecated "legacy" policy or any unrecognized custom policy. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureUserAppConsentControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Move the tenant off the deprecated "microsoft-user-default-legacy" consent policy onto "microsoft-user-default-recommended" (or disable user consent entirely and route all app installs through an admin consent workflow, see AC-002).'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/defaultuserrolepermissions?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies'
        'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic -- that source additionally cross-references a live delegated-permission-classification API against its own curated dangerous-permission list to further sub-classify the "-low" policy''s own specific permissions; this project judged that extra granularity unnecessary complexity relative to the core question (is the tenant still on the deprecated unrestricted policy). Built-in policy ID semantics (legacy/low/recommended) confirmed against Microsoft''s own "Manage app consent policies" guidance, re-fetched 2026-08-08. permissionGrantPoliciesAssigned was already collected for AC-001''s own future use before this control existed.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'USR-004' }
    )

    baselineDependency = $null
}
