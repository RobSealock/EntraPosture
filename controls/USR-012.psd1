@{
    <#
        VNext build order item 2, the 109-row backlog continuation past its original close-out
        (batch 12, 2026-08-08, built in ranked-value order per the project owner's own priority
        list). New UserRegistrationDetails collector -- see NormalizeUserRegistrationDetails.ps1's
        own header comment for why this uses the bulk registration-details report instead of a
        per-user /authentication/methods N+1 fetch. Keys deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'USR-012'
    version     = '1.0.0'
    title       = 'Users Without Registered MFA Factors'
    description = 'For each user with a collected UserRegistrationDetails record, checks isMfaRegistered.'
    rationale   = 'A user with no MFA factor registered is protected by password alone -- a single leaked or guessed credential is enough to fully compromise the account, with no second factor to stop it.'
    severity    = 2
    category    = 'Identity'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('UserRegistrationDetails')
    requiredPermissions     = @(
        @{ scope = 'AuditLog.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per collected UserRegistrationDetails record (the underlying report already excludes disabled and soft-deleted users). NotApplicable (a single tenant-scoped result) if no such record was collected at all.'

    reasonCodes = @(
        @{ code = 'USR-012-NO-MFA-REGISTERED';        resultStatus = 'Fail';         description = 'The user has not registered any strong authentication method for multifactor authentication.' }
        @{ code = 'USR-012-MFA-REGISTERED';           resultStatus = 'Pass';        description = 'The user has registered a strong authentication method for multifactor authentication.' }
        @{ code = 'USR-012-NO-REGISTRATION-DETAILS';  resultStatus = 'NotApplicable'; description = 'No UserRegistrationDetails entity was present in the evidence set.' }
        @{ code = 'USR-012-EVIDENCE-NOT-COLLECTED';   resultStatus = 'NotEvaluated'; description = 'UserRegistrationDetails evidence was not fully collected for this snapshot -- including a tenant not licensed for Entra ID P1/P2, which this report requires.' }
        @{ code = 'USR-012-EVALUATOR-ERROR';          resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per collected UserRegistrationDetails record. Fail if isMfaRegistered is false, Pass if true. NotApplicable (single tenant-scoped result) only if zero records exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer -- notably, an Entra ID tenant not licensed for P1/P2 surfaces as USR-012-EVIDENCE-NOT-COLLECTED, not a silent Pass.'

    evaluatorFunctionName  = 'Test-EntraPostureUserMfaRegistrationControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Require affected users to register a strong authentication method (Microsoft Authenticator, FIDO2 security key, Windows Hello for Business) and enforce MFA for all sign-ins via Conditional Access.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity (consolidates EF-USR-009 "No MFA factor registered"), not a port of EntraFalcon''s own source logic. Originally deferred in §36 pending an evidence-path decision between the per-user /authentication/methods API (polymorphic, N+1, and explicitly discouraged by Microsoft''s own documentation for bulk auditing) and the bulk /reports/authenticationMethods/userRegistrationDetails report (chosen here) -- confirmed directly against live Microsoft Graph documentation, re-fetched 2026-08-08, including the exact wording of Microsoft''s own recommendation against the per-user approach for this use case.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'USR-012' }
    )

    baselineDependency = $null
}
