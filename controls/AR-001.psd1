@{
    <#
        Relational control (Phase 7, second tier): correlates AccessReviewDefinition scope
        query strings against a curated set of governance-surface patterns to determine which
        surfaces have no coverage at all. Cannot be evaluated from a single definition in
        isolation -- the applicable unit is "does *any* definition cover this surface." Keys are
        deliberately camelCase -- see XTA-001.psd1's header comment for why.

        Simplified from 15-feature-parity-matrix.md section 7's full AR-001 design in three
        ways, each documented in 00-open-questions.md's Phase 7 section:
          1. Covers three surfaces (Privileged Roles, Groups, Applications), not four -- "Guests"
             is dropped because this project's collected scopeQuery field (a single string) does
             not reliably distinguish a guest-scoped review from a general group-membership
             review without deeper query-parameter parsing not attempted here.
          2. Does not check recurrence activity (settings.recurrence is not in this project's
             AccessReviewDefinition evidence field allowlist -- src/Normalization/
             NormalizeAccessReviewDefinition.ps1 collects status/scopeQuery/descriptionForAdmins
             only). A lapsed one-time review and an active recurring one are treated the same:
             both count as "covered."
          3. Surface detection is substring matching against scopeQuery, not independently
             re-verified against a live tenant's actual query string shapes this session --
             flagged for the same follow-up verification pass already tracked for other controls'
             citations.
          4. Does not implement the licensing-gate NotApplicable distinction (Entra ID
             Governance/Entra Suite/P2) -- license state is not currently collected evidence.
          5. Does not implement the Global-Reader-role-scope-review coverage gap the matrix
             documents -- this project's preflight/coverage model does not yet distinguish
             permission scope at that granularity for this collector.
    #>
    controlId   = 'AR-001'
    version     = '1.0.0'
    title       = 'No Access Review Covers Privileged Roles, Groups, or Application Access'
    description = 'For each of three governance surfaces -- privileged Entra role assignments, groups, and application access -- checks whether at least one AccessReviewDefinition''s scope query targets that surface at all.'
    rationale   = 'Microsoft names privileged-role recertification and group/app periodic justification among the primary reasons to use access reviews. Absent any review targeting a surface, access on that surface accumulates and is never proactively reconfirmed -- the same silent-drift-from-intent failure mode this project''s other governance-process controls target, applied to standing access instead of policy composition.'
    severity    = 3
    category    = 'Access Reviews / Governance'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AccessReviewDefinition')
    requiredPermissions     = @(
        @{ scope = 'AccessReview.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable -- evaluated once per surface (three results per assessment) regardless of how many AccessReviewDefinition entities exist, including zero.'

    reasonCodes = @(
        @{ code = 'AR-001-NO-REVIEW-PRIVILEGED-ROLES'; resultStatus = 'Fail'; description = 'No AccessReviewDefinition''s scopeQuery matches a privileged-role-assignment pattern.' }
        @{ code = 'AR-001-NO-REVIEW-GROUPS';           resultStatus = 'Fail'; description = 'No AccessReviewDefinition''s scopeQuery matches a group-membership pattern.' }
        @{ code = 'AR-001-NO-REVIEW-APPLICATIONS';     resultStatus = 'Fail'; description = 'No AccessReviewDefinition''s scopeQuery matches an application-assignment pattern.' }
        @{ code = 'AR-001-COVERAGE-CONFIRMED';         resultStatus = 'Pass'; description = 'At least one AccessReviewDefinition''s scopeQuery matches this surface''s pattern.' }
        @{ code = 'AR-001-EVIDENCE-NOT-COLLECTED';     resultStatus = 'NotEvaluated'; description = 'AccessReviewDefinition evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AR-001-EVALUATOR-ERROR';            resultStatus = 'Error'; description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per surface (three per assessment). Fail if no collected AccessReviewDefinition''s scopeQuery matches that surface''s detection pattern -- including when zero definitions exist at all (all three surfaces Fail). Pass if at least one does. This control does not judge whether a matching review is healthy, recurring, or complete -- only whether the surface has any review targeting it. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureAccessReviewCoverageControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Create a recurring access review for each uncovered surface -- self-review or owner/manager-reviewed per Microsoft''s documented guidance -- with a defined recurrence, not a one-time review that will silently lapse.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview'
        'https://learn.microsoft.com/en-us/graph/api/accessreviewset-list-definitions?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Clean-room control authored directly from Microsoft Learn access-reviews guidance and 15-feature-parity-matrix.md section 7's AR-001 design, narrowed per this file's own header comment to the three surfaces and coverage-only (no recurrence-activity) check this project's current evidence supports. References not independently re-fetched/re-verified as live URLs during this Phase 7 authoring session."
    }

    externalMappings = @()

    baselineDependency = @{
        documentationUrl  = 'https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview'
        asOfDate          = '2026-04-09'
        citationStrength  = 'Inference'
    }
}
