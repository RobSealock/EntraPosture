@{
    <#
        VNext build order item 13 (agent identity / PIM-for-Groups). PIMG-001/002 are NOT part
        of the canonical AGT-* numbering -- per 15-feature-parity-matrix.md section 11, they are
        this project's own addition, a distinct area EntraFalcon's own findings don't cover, not
        a consolidated EntraFalcon finding the way AGT-001-017 are. Keys are deliberately
        camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'PIMG-001'
    version     = '1.0.0'
    title       = 'Role-Assignable Group Has Standing (Non-PIM) Membership Despite PIM-for-Groups Being Configured'
    description = 'For each role-assignable Group with at least one PIM-for-Groups membership eligibility schedule instance configured, checks whether any of its actual current members bypass PIM entirely -- present as a direct TransitiveMemberOf member with no corresponding PIM eligibility or active-assignment record for that principal.'
    rationale   = 'The same "presence of a governance mechanism proves nothing if bypassed" concern PIM-002 already applies to directory roles, generalized to groups: configuring PIM-for-Groups membership eligibility does not, by itself, prevent someone from being added to the group directly through the ordinary Groups API. A role-assignable group with PIM-for-Groups configured but also standing membership PIM has no record of at all gives a false impression of governed access.'
    severity    = 3
    category    = 'PIM'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('Group', 'TransitiveMemberOf', 'PimEligible', 'PimActive')
    requiredPermissions     = @(
        @{ scope = 'Group.Read.All'; confirmed = $true }
        @{ scope = 'GroupMember.Read.All'; confirmed = $true }
        @{ scope = 'PrivilegedEligibilitySchedule.Read.AzureADGroup'; confirmed = $true }
        @{ scope = 'PrivilegedAssignmentSchedule.Read.AzureADGroup'; confirmed = $true }
    )

    applicability = 'Evaluated once per role-assignable Group entity with at least one PimEligible (accessId ''member'') relationship configured. NotApplicable (a single tenant-scoped result) if no role-assignable group has PIM-for-Groups membership eligibility configured at all.'

    reasonCodes = @(
        @{ code = 'PIMG-001-STANDING-MEMBERSHIP-OUTSIDE-PIM'; resultStatus = 'Fail';         description = 'At least one current member of the group has no corresponding PIM-for-Groups eligibility or active-assignment record.' }
        @{ code = 'PIMG-001-MEMBERSHIP-GOVERNED-BY-PIM';      resultStatus = 'Pass';        description = 'Every current member of the group is accounted for by a PIM-for-Groups eligibility or active-assignment record.' }
        @{ code = 'PIMG-001-NO-GROUPS-WITH-PIM-CONFIGURED';   resultStatus = 'NotApplicable'; description = 'No role-assignable Group entity has PIM-for-Groups membership eligibility configured in the evidence set.' }
        @{ code = 'PIMG-001-EVIDENCE-NOT-COLLECTED';          resultStatus = 'NotEvaluated'; description = 'Group, TransitiveMemberOf, PimEligible, or PimActive evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'PIMG-001-EVALUATOR-ERROR';                 resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per role-assignable Group entity that has PIM-for-Groups membership eligibility configured. Fail if any TransitiveMemberOf member has no corresponding PimEligible or PimActive (accessId ''member'') relationship for that group, Pass if every member is accounted for. A role-assignable group with no PIM-for-Groups membership eligibility configured at all produces no result for it. NotApplicable (single tenant-scoped result) only if zero groups have PIM-for-Groups membership eligibility configured. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPosturePimForGroupsStandingMembershipControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Remove the standing (non-PIM) member from the group, or bring their access under PIM-for-Groups governance by creating a corresponding eligibility schedule for them.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/privilegedaccessgroup-list-eligibilityscheduleinstances?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/groups-list?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'This project''s own addition, not derived from EntraFalcon (per 15-feature-parity-matrix.md section 11''s own text: "a distinct area EntraFalcon''s own findings don''t cover"). Endpoint, $filter requirement (groupId or principalId only, no unfiltered tenant-wide list), and permission scope confirmed live against the "List eligibilityScheduleInstances" Graph reference page, re-fetched 2026-08-07.'
    }

    externalMappings = @()

    baselineDependency = $null
}
