@{
    <#
        Relational/temporal control (v.next build order item 11), admitted into v1 scope by the
        deviation record in 00-open-questions.md item 28 -- see 15-feature-parity-matrix.md
        section 8 for the full design this control implements. Keys are deliberately camelCase
        -- see XTA-001.psd1's header comment for why.

        Notable, favorable departure from the matrix's own speculative design: the matrix
        anticipated needing to independently compute "has this assignment's schedule expired"
        against the wall clock (the same kind of time-relative check AR-002's overdue evaluator
        needs). Live verification against Microsoft's accessPackageAssignment resource page found
        this project doesn't need to -- `state: expired` is a real, distinct, platform-computed
        value this project can read directly, avoiding a second time-relative evaluator in this
        registry. Whether an `expired`-state record still represents live access, or is purely a
        historical record of access already removed, remains genuinely unconfirmed by Microsoft's
        documentation -- the matrix's own open question on this exact point is preserved as
        Inference-tier, not resolved by assumption.

        Same "privileged resource role" definition and same license-gate omission as EM-001 --
        see EM-001.psd1's own header comment for the reasoning, not repeated here.
    #>
    controlId   = 'EM-002'
    version     = '1.0.0'
    title       = 'Access Package Policy Grants Indefinite Access or Has Assignments Past Expiration'
    description = 'For each access package EM-001 would establish as privileged, checks whether any attached assignment policy grants access with no expiration at all, and whether any of that package''s assignments are in a past-expiration (expired) state.'
    rationale   = 'Entitlement management''s whole stated value proposition is ensuring identities don''t retain access indefinitely through time-limited assignments -- a policy that explicitly opts out of that (noExpiration) on a privileged-resource package defeats the mechanism''s own purpose. This is the AR-002 pattern (presence of a governance mechanism proves nothing if it''s configured to do nothing) applied to entitlement management''s own lifecycle field instead of access-review instance health.'
    severity    = 2
    category    = 'Entitlement Management'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AccessPackage', 'AccessPackageAssignmentPolicy', 'AccessPackageAssignment', 'Group', 'AzureRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'EntitlementManagement.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per assignment policy attached to a privileged access package (same privileged-resource-role gate as EM-001), plus once per that package''s assignment currently in state ''expired''. A single tenant-scoped NotApplicable result is produced if no access package anywhere is privileged.'

    reasonCodes = @(
        @{ code = 'EM002-POLICY-NO-EXPIRATION';        resultStatus = 'Fail'; description = 'A privileged-resource package''s assignment policy has expiration.type set to ''noExpiration''.' }
        @{ code = 'EM002-ASSIGNMENT-PAST-EXPIRATION';  resultStatus = 'Fail'; description = 'A privileged-resource package''s assignment is in state ''expired''.' }
        @{ code = 'EM002-EXPIRATION-ENFORCED';         resultStatus = 'Pass'; description = 'A privileged-resource package''s assignment policy has a bounded (afterDateTime/afterDuration) expiration configured.' }
        @{ code = 'EM002-NO-APPLICABLE-POLICIES';      resultStatus = 'NotApplicable'; description = 'No access package''s resource roles resolve to a role-assignable or Azure-role-bearing group, or a privileged-resource package exists but has zero attached policies and zero stale assignments to evaluate.' }
        @{ code = 'EM002-EVIDENCE-NOT-COLLECTED';      resultStatus = 'NotEvaluated'; description = 'AccessPackage/AccessPackageAssignmentPolicy/AccessPackageAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'EM002-EVALUATOR-ERROR';             resultStatus = 'Error'; description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per assignment policy attached to a privileged-resource package (Fail if expiration.type is noExpiration, Pass otherwise), plus one result per that package''s assignment in state ''expired'' (always Fail). A single tenant-scoped NotApplicable result is produced instead if no package anywhere is privileged. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself. This control never stores an assignment''s target principal -- only the assignment''s own ID and state, per the matrix''s own redaction guidance (see NormalizeAccessPackageAssignment.ps1).'

    evaluatorFunctionName  = 'Test-EntraPostureAccessPackageExpirationEnforcementControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Set an explicit afterDuration or afterDateTime expiration on any policy governing privileged resources instead of noExpiration; investigate why any past-expiration (state=expired) assignment is still present and confirm whether the underlying access has actually been removed.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview'
        'https://learn.microsoft.com/en-us/graph/api/resources/expirationpattern?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/accesspackageassignment?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/entitlementmanagement-list-assignments?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Clean-room control authored directly from Microsoft Graph's expirationPattern/accessPackageAssignment resource documentation (all four references above fetched live during this build-order item, including the 'List accessPackageAssignments' operation page confirming a tenant-wide, non-N+1 list call) and 15-feature-parity-matrix.md section 8's EM-002 design. The matrix's own open question about whether Microsoft's platform ever surfaces a past-expiration assignment is answered structurally (state='expired' is a real enum value) but not semantically (whether it still represents live access) -- left as Inference, stated plainly rather than assumed either way. Admitted into v1 scope by the deviation record in 00-open-questions.md item 28."
    }

    externalMappings = @()

    baselineDependency = @{
        documentationUrl  = 'https://learn.microsoft.com/en-us/graph/api/resources/accesspackageassignment?view=graph-rest-1.0'
        asOfDate          = '2026-08-07'
        citationStrength  = 'Inference'
    }
}
