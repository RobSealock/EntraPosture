@{
    <#
        VNext build order item 2, new-evidence phase (batch 8, 2026-08-08). New
        UserSignInActivity collector, P1/P2-licensed and AuditLog.Read.All-gated -- see
        CollectUserSignInActivity.ps1's own header comment for why this is a wholly separate
        collector from CollectUsers.ps1, not a field extension to it. Keys deliberately camelCase
        -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'USR-005'
    version     = '1.0.0'
    title       = 'Inactive Users'
    description = 'For each User entity, checks whether it has gone at least 180 days without a successful sign-in (or, for a user with no recorded successful sign-in at all, whether the account itself is older than 180 days).'
    rationale   = 'A dormant account is unnecessary standing attack surface -- any role, group membership, or application access it retains is exposed with no legitimate ongoing use, and a dormant account taken over is less likely to be noticed quickly by its own nominal owner.'
    severity    = 2
    category    = 'Identity'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('User', 'UserSignInActivity')
    requiredPermissions     = @(
        @{ scope = 'User.Read.All'; confirmed = $true }
        @{ scope = 'AuditLog.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per collected User entity. NotApplicable (a single tenant-scoped result) only if the tenant has no users at all.'

    reasonCodes = @(
        @{ code = 'USR-005-INACTIVE-SINCE-LAST-SIGN-IN';        resultStatus = 'Fail';         description = 'The user last successfully signed in 180 or more days ago.' }
        @{ code = 'USR-005-ACTIVE';                              resultStatus = 'Pass';        description = 'The user last successfully signed in fewer than 180 days ago.' }
        @{ code = 'USR-005-NEVER-SIGNED-IN';                     resultStatus = 'Fail';         description = 'The user has no recorded successful sign-in and the account is more than 180 days old.' }
        @{ code = 'USR-005-NEW-ACCOUNT-NOT-YET-SIGNED-IN';       resultStatus = 'Pass';        description = 'The user has no recorded successful sign-in but the account is 180 days old or less (grace period).' }
        @{ code = 'USR-005-NO-TEMPORAL-SIGNAL';                  resultStatus = 'Pass';        description = 'Neither a recorded sign-in nor a known account creation date is available for this user.' }
        @{ code = 'USR-005-NO-USERS';                            resultStatus = 'NotApplicable'; description = 'No User entity was present in the evidence set.' }
        @{ code = 'USR-005-EVIDENCE-NOT-COLLECTED';              resultStatus = 'NotEvaluated'; description = 'User or UserSignInActivity evidence was not fully collected for this snapshot -- including a tenant not licensed for Entra ID P1/P2, which signInActivity itself requires.' }
        @{ code = 'USR-005-EVALUATOR-ERROR';                     resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per collected User entity. Fail if the user last successfully signed in 180+ days ago, or has never successfully signed in and the account is more than 180 days old; Pass otherwise (including the narrow case of no temporal signal at all, and a new account still within its 180-day grace period). The overall tenant-scoped NotApplicable applies only when zero users exist in evidence at all. Compares against the wall clock at evaluation time, not collection time -- re-evaluating the same sealed snapshot later can change this specific result, the same documented behavior AR-002''s evaluator already established. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself -- notably, an Entra ID tenant not licensed for P1/P2 will surface as USR-005-EVIDENCE-NOT-COLLECTED (UserSignInActivity Denied/Unavailable at the collector level), not a silent Pass.'

    evaluatorFunctionName  = 'Test-EntraPostureInactiveUserControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Disable or remove accounts with no legitimate ongoing need for access. If an account must remain provisioned for a known future need, document why and re-review on a fixed schedule rather than leaving it indefinitely dormant.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/signinactivity?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-manage-inactive-user-accounts'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity (consolidates EF-USR-011 "Inactive"), not a port of EntraFalcon''s own source logic -- the 180-day threshold and the lastSuccessfulSignInDateTime/createdDateTime two-signal shape were independently re-derived by reading EntraFalcon''s own publicly visible check_Users.psm1 (github.com/CompassSecurity/EntraFalcon), then confirmed each field/permission/licensing claim directly against live Microsoft Graph documentation (re-fetched 2026-08-08), not assumed from the source alone. Deliberately does not replicate that source''s further "Cloud Sync service account" UPN-prefix exemption -- see the evaluator''s own DESCRIPTION.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'USR-005' }
    )

    baselineDependency = $null
}
