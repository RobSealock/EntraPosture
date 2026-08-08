@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Keys
        deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'PAS-005'
    version     = '1.0.0'
    title       = 'Self-Service Password Reset is Enabled for Administrators'
    description = 'Checks the tenant''s AuthorizationPolicy.allowedToUseSSPR setting.'
    rationale   = 'Administrator accounts are the highest-value targets in the directory -- allowing them to reset their own password via SSPR (typically satisfied by two of email/SMS/phone-call/Authenticator, several of which an attacker with a compromised personal device or account could also satisfy) widens the admin account takeover surface beyond a dedicated, closely governed reset process.'
    severity    = 2
    category    = 'Passwords'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AuthorizationPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per AuthorizationPolicy entity (in practice, exactly one). NotApplicable (a single tenant-scoped result) if the singleton is missing from evidence entirely.'

    reasonCodes = @(
        @{ code = 'PAS-005-ADMIN-SSPR-ALLOWED';    resultStatus = 'Fail';         description = 'Administrators of the tenant are allowed to use Self-Service Password Reset.' }
        @{ code = 'PAS-005-ADMIN-SSPR-DISALLOWED'; resultStatus = 'Pass';        description = 'Administrators of the tenant are not allowed to use Self-Service Password Reset.' }
        @{ code = 'PAS-005-NO-POLICY-FOUND';       resultStatus = 'NotApplicable'; description = 'No AuthorizationPolicy entity was present in the evidence set.' }
        @{ code = 'PAS-005-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'AuthorizationPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'PAS-005-EVALUATOR-ERROR';       resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AuthorizationPolicy entity (in practice exactly one). Fail if allowedToUseSSPR is true, Pass if false. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureAdminSelfServicePasswordResetControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Disable SSPR for administrator accounts: Connect-MgGraph -Scopes Policy.ReadWrite.Authorization; Update-MgPolicyAuthorizationPolicy -AllowedToUseSspr:$false.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy?tabs=ms-powershell#administrator-reset-policy-differences'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. allowedToUseSSPR confirmed present on the same default GET /v1.0/policies/authorizationPolicy response already used by COL-001/002/USR-001/GRP-001, re-fetched 2026-08-08 -- no collector change beyond the normalizer field addition.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PAS-005' }
    )

    baselineDependency = $null
}
