@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08, batch
        4). Control ID/title reused from 15-feature-parity-matrix.md section 3.3's "External
        Collaboration" set -- confirmed a standalone canonical finding ("new -- no §3.2
        counterpart"), the same COL-002 already established. Keys camelCase.
    #>
    controlId   = 'COL-001'
    version     = '1.0.0'
    title       = 'Guest Access Level Not Set to Restricted'
    description = 'Checks the tenant''s AuthorizationPolicy guestUserRoleId setting. Fails unless it is set to the Restricted Guest User well-known role (2af84b1e-32c8-42b7-82bc-daa82404023b), the most restrictive of Microsoft''s three documented options.'
    rationale   = 'A guest granted the default "Guest User" role (or, more permissively, the "User" role) can read more of the directory (other users, groups, and their properties) than the "Restricted Guest User" role allows -- broader directory visibility for external identities than most tenants intend by default.'
    severity    = 2
    category    = 'External Collaboration'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AuthorizationPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per AuthorizationPolicy entity (in practice, exactly one per tenant). NotApplicable (a single tenant-scoped result) if no AuthorizationPolicy entity is present in evidence.'

    reasonCodes = @(
        @{ code = 'COL-001-GUEST-ACCESS-RESTRICTED';     resultStatus = 'Pass';        description = 'guestUserRoleId is set to Restricted Guest User.' }
        @{ code = 'COL-001-GUEST-ACCESS-NOT-RESTRICTED'; resultStatus = 'Fail';         description = 'guestUserRoleId is set to User or Guest User, not Restricted Guest User.' }
        @{ code = 'COL-001-NO-POLICY-FOUND';             resultStatus = 'NotApplicable'; description = 'No AuthorizationPolicy entity was present in the evidence set.' }
        @{ code = 'COL-001-EVIDENCE-NOT-COLLECTED';      resultStatus = 'NotEvaluated'; description = 'AuthorizationPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'COL-001-EVALUATOR-ERROR';             resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AuthorizationPolicy entity. Pass if guestUserRoleId equals the Restricted Guest User role template ID, Fail otherwise. NotApplicable (single tenant-scoped result) only if zero AuthorizationPolicy entities exist in evidence. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureGuestAccessLevelControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Set guestUserRoleId to the Restricted Guest User role (2af84b1e-32c8-42b7-82bc-daa82404023b) in External Identities settings, unless a specific, reviewed business need requires broader guest directory visibility.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. The three well-known guestUserRoleId GUIDs confirmed directly against the live authorizationPolicy Graph reference page, re-fetched 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'COL-001' }
    )

    baselineDependency = $null
}
