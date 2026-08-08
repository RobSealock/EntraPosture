@{
    <#
        Relational and temporal control (VNext build order item 9, second AR-tier): gated on
        AR-001 exactly the way AUTHCTX-002 gates on AUTHCTX-001 -- only evaluates instances of
        AccessReviewDefinitions that AR-001 would already confirm cover a governance surface.
        Keys are deliberately camelCase -- see XTA-001.psd1's header comment for why.

        Scoped down from 15-feature-parity-matrix.md section 7's full AR-002 design in ways this
        project owns and documents rather than silently assumes:
          1. Only the most recent instance per applicable definition is evaluated, not historical
             ones -- the matrix itself leaves "should historical instances also be evaluated" as
             an explicitly open, unresolved Phase 7 question ("affects both evidence volume and
             whether 'was healthy once, isn't now' drift is detectable"). This project's answer:
             most-recent-only, to bound both collection cost (a real two-level N+1: definitions
             -> instances -> decisions) and evidence volume, matching how every other control in
             this registry sizes its applicable set. Historical-instance drift detection is
             deferred to whenever this project's drift-detection work (VNext build order item 10)
             is designed, not solved here.
          2. The "materially incomplete" not-reviewed threshold is a project-owned round number
             (50%), not a Microsoft directive or a number derived from real tenant data -- the
             matrix explicitly says this "needs a concrete number chosen with real tenant data,
             not guessed here." Matches the precedent already set by PRIV-001's 2-4 admin range
             and PIM-003's 4-hour threshold: stated plainly as this project's own judgment call,
             not cited as Microsoft guidance.
          3. Overdue determination compares against the wall clock at evaluation time, not
             collection time -- the only time-relative evaluator in this registry. Re-evaluating
             the same sealed snapshot at two different real-world times can produce a different
             AR-002-INSTANCE-OVERDUE determination even though the underlying evidence file
             never changed. This is documented behavior (see the evaluator's own DESCRIPTION),
             not a hidden inconsistency.
          4. Does not distinguish Azure-resource-role vs Entra-role reviews within the
             surface-coverage gate -- inherits this from AR-001, which the matrix also lists as
             an open question not resolved there either.
    #>
    controlId   = 'AR-002'
    version     = '1.0.0'
    title       = 'Existing Access Reviews Are Stale, Incomplete, or Have Unapplied Decisions'
    description = 'For each AccessReviewDefinition that AR-001 confirms covers a governance surface, checks whether its most recent instance is overdue, has decisions that were never applied, or is materially incomplete.'
    rationale   = 'A review that merely exists (what AR-001 checks) is not the same as a review that is actually functioning -- an access review with no active recurrence, that nobody ever finishes, or whose decisions are recorded but never applied, provides the appearance of governance without its substance. This is a distinct, additive failure mode from AR-001''s "does anything even target this surface" check.'
    severity    = 3
    category    = 'Access Reviews / Governance'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AccessReviewDefinition', 'AccessReviewInstance')
    requiredPermissions     = @(
        @{ scope = 'AccessReview.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per (definition, most-recent-instance) pair, for every AccessReviewDefinition that matches one of AR-001''s three governance-surface patterns and has at least one collected instance. A surface with zero AR-001 coverage, or a covering definition with no instance yet (e.g. Draft, never started a cycle), produces no result for that definition -- and a single tenant-scoped NotApplicable if this is true for every covering definition.'

    reasonCodes = @(
        @{ code = 'AR-002-INSTANCE-OVERDUE';       resultStatus = 'Fail'; description = 'The instance''s scheduled endDateTime has passed but its status is not a terminal completed state (Completed/AutoReviewed).' }
        @{ code = 'AR-002-DECISIONS-NOT-APPLIED';   resultStatus = 'Fail'; description = 'The instance completed with at least one decision recorded, automatic apply is disabled, and none of the decisions have been applied.' }
        @{ code = 'AR-002-MATERIALLY-INCOMPLETE';   resultStatus = 'Fail'; description = 'The instance completed with more than 50% of its decisions never reviewed.' }
        @{ code = 'AR-002-HEALTHY';                 resultStatus = 'Pass'; description = 'The instance is not overdue and shows no unapplied or materially incomplete decisions as of evaluation time.' }
        @{ code = 'AR-002-NO-APPLICABLE-INSTANCES'; resultStatus = 'NotApplicable'; description = 'No AR-001-covering AccessReviewDefinition has any collected instance yet to evaluate.' }
        @{ code = 'AR-002-EVIDENCE-NOT-COLLECTED';  resultStatus = 'NotEvaluated'; description = 'AccessReviewDefinition/AccessReviewInstance evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AR-002-EVALUATOR-ERROR';         resultStatus = 'Error'; description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per (definition, instance) pair evaluated, or a single tenant-scoped NotApplicable result if none are applicable. Fail if AR-002-INSTANCE-OVERDUE, AR-002-DECISIONS-NOT-APPLIED, or AR-002-MATERIALLY-INCOMPLETE applies, checked in that priority order (an instance that has not yet reached a terminal status is judged only on overdue-ness, not decision completeness, since it may legitimately still be in progress); Pass otherwise, including an in-progress instance that is not yet past its end date. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself. This control never stores individual reviewer identities or per-principal decision outcomes -- only aggregate decision counts, per the matrix''s own explicit redaction requirement (see NormalizeAccessReviewInstance.ps1).'

    evaluatorFunctionName  = 'Test-EntraPostureAccessReviewInstanceHealthControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Investigate and close out any overdue instance; if automatic apply is not enabled, manually apply completed reviews'' decisions promptly; for instances left materially incomplete, follow up directly with the assigned reviewers or reassign the review before its next cycle.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/accessreviewscheduledefinition-list-instances?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/accessreviewinstance?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/accessreviewinstance-list-decisions?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/accessreviewinstancedecisionitem?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/accessreviewschedulesettings?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Clean-room control authored directly from Microsoft Graph's accessReviewInstance/accessReviewInstanceDecisionItem/accessReviewScheduleSettings resource documentation (all five references above fetched live during this build-order item, not assumed by analogy) and 15-feature-parity-matrix.md section 7's AR-002 design, narrowed per this file's own header comment (most-recent-instance-only, a project-owned 50% incompleteness threshold, evaluation-time overdue determination). Per docs/VNext.md's review-not-reuse policy: no external reference-repo source was read for this control's logic."
    }

    externalMappings = @()

    baselineDependency = @{
        documentationUrl  = 'https://learn.microsoft.com/en-us/graph/api/resources/accessreviewinstance?view=graph-rest-1.0'
        asOfDate          = '2026-08-07'
        citationStrength  = 'Inference'
    }
}
