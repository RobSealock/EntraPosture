@{
    <#
        VNext build order item 13. See PIMG-001.psd1's header comment for this control's shared
        build-order/provenance context (this project's own addition, not an EntraFalcon-derived
        finding). Keys are deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'PIMG-002'
    version     = '1.0.0'
    title       = 'PIM-for-Groups Active Assignment Allows Permanent (No-Expiration) Access'
    description = 'For each role-assignable Group with at least one PIM-for-Groups active-assignment schedule instance, checks whether any instance has no expiration (validity.endDateTime is null).'
    rationale   = 'Directly parallel to PIM-005''s "Tier-0 Roles Allow Permanent Active Assignments" concern, applied to groups: a PIM-for-Groups active assignment with no expiration defeats the time-bounded-access purpose PIM-for-Groups exists to provide, the same way a permanent directly-assigned directory role does.'
    severity    = 2
    category    = 'PIM'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('Group', 'PimActive')
    requiredPermissions     = @(
        @{ scope = 'Group.Read.All'; confirmed = $true }
        @{ scope = 'PrivilegedAssignmentSchedule.Read.AzureADGroup'; confirmed = $true }
    )

    applicability = 'Evaluated once per role-assignable Group entity with at least one PIM-for-Groups active-assignment schedule instance (PimActive relationship). NotApplicable (a single tenant-scoped result) if no role-assignable group has a PIM-for-Groups active assignment at all.'

    reasonCodes = @(
        @{ code = 'PIMG-002-PERMANENT-ASSIGNMENT-ALLOWED';         resultStatus = 'Fail';         description = 'At least one PIM-for-Groups active-assignment schedule instance for this group has no expiration.' }
        @{ code = 'PIMG-002-EXPIRATION-REQUIRED';                  resultStatus = 'Pass';        description = 'Every PIM-for-Groups active-assignment schedule instance for this group has an expiration.' }
        @{ code = 'PIMG-002-NO-GROUPS-WITH-ACTIVE-ASSIGNMENTS';    resultStatus = 'NotApplicable'; description = 'No role-assignable Group entity has a PIM-for-Groups active-assignment schedule instance in the evidence set.' }
        @{ code = 'PIMG-002-EVIDENCE-NOT-COLLECTED';               resultStatus = 'NotEvaluated'; description = 'Group or PimActive evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'PIMG-002-EVALUATOR-ERROR';                      resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per role-assignable Group entity with at least one PimActive relationship. Fail if any such relationship has validity.endDateTime null, Pass if every one has a non-null expiration. A role-assignable group with zero PIM-for-Groups active assignments produces no result for it. NotApplicable (single tenant-scoped result) only if zero groups have any PIM-for-Groups active assignment. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPosturePimForGroupsPermanentAssignmentControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Set an expiration on the active assignment, or re-create it as a time-bounded assignment through PIM-for-Groups activation rather than a permanent direct assignment.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/privilegedaccessgroup-list-assignmentscheduleinstances?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'This project''s own addition, not derived from EntraFalcon. Reads validity.endDateTime directly off the collected PimActive relationship (null means no expiration) -- confirmed directly against the live "List assignmentScheduleInstances" Graph reference page''s own example response, re-fetched 2026-08-07, which returned a flat endDateTime field rather than the nested scheduleInfo.expiration.type the original design spec (15-feature-parity-matrix.md section 11) speculated about before this endpoint was actually checked.'
    }

    externalMappings = @()

    baselineDependency = $null
}
