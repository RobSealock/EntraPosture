@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08). Control
        ID/title reused from 15-feature-parity-matrix.md section 3.3's "External Collaboration"
        set -- confirmed a standalone canonical finding ("new -- no §3.2 counterpart"), not a
        consolidation, unlike the Groups-section rows this same batch pass initially
        misidentified as buildable (see 00-open-questions.md's writeup). Keys camelCase.
    #>
    controlId   = 'COL-002'
    version     = '1.0.0'
    title       = 'Weak Guest Invite Settings'
    description = 'Checks the tenant''s AuthorizationPolicy allowInvitesFrom setting. Fails when set to everyone or adminsGuestInvitersAndAllMembers (either lets ordinary members invite guests).'
    rationale   = 'Unrestricted guest invitation lets any tenant member (or, in the broadest setting, any external guest) add new external identities into the directory -- an uncontrolled expansion of the tenant''s own trust boundary that bypasses admin review entirely.'
    severity    = 2
    category    = 'External Collaboration'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AuthorizationPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per AuthorizationPolicy entity (in practice, exactly one per tenant). NotApplicable (a single tenant-scoped result) if no AuthorizationPolicy entity is present in evidence.'

    reasonCodes = @(
        @{ code = 'COL-002-GUEST-INVITE-UNRESTRICTED'; resultStatus = 'Fail';         description = 'allowInvitesFrom is everyone or adminsGuestInvitersAndAllMembers.' }
        @{ code = 'COL-002-GUEST-INVITE-RESTRICTED';   resultStatus = 'Pass';        description = 'allowInvitesFrom is adminsAndGuestInviters or none.' }
        @{ code = 'COL-002-NO-POLICY-FOUND';           resultStatus = 'NotApplicable'; description = 'No AuthorizationPolicy entity was present in the evidence set.' }
        @{ code = 'COL-002-EVIDENCE-NOT-COLLECTED';    resultStatus = 'NotEvaluated'; description = 'AuthorizationPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'COL-002-EVALUATOR-ERROR';           resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AuthorizationPolicy entity. Fail if allowInvitesFrom is everyone or adminsGuestInvitersAndAllMembers, Pass if adminsAndGuestInviters or none. NotApplicable (single tenant-scoped result) only if zero AuthorizationPolicy entities exist in evidence. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureGuestInviteRestrictionControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Set allowInvitesFrom to adminsAndGuestInviters (or none, if guest invitations should be fully centralized/disabled) in External Identities settings.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. allowInvitesFrom enum values confirmed live against the authorizationPolicy Graph reference page, re-fetched 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'COL-002' }
    )

    baselineDependency = $null
}
