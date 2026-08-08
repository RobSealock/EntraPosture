@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Keys
        deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'GRP-003'
    version     = '1.0.0'
    title       = 'Public M365 Groups'
    description = 'For each Group entity, checks whether it is a statically-membered, publicly-visible Microsoft 365 (unified) group.'
    rationale   = 'Anyone in the tenant can join a public group without owner approval, immediately gaining access to its Team, SharePoint site, and shared mailbox -- an unintended-access surface that scales with group count if left unmanaged.'
    severity    = 2
    category    = 'Groups'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('Group')
    requiredPermissions     = @(
        @{ scope = 'Group.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per collected Group entity. NotApplicable (a single tenant-scoped result) only if the tenant has no groups at all.'

    reasonCodes = @(
        @{ code = 'GRP-003-PUBLIC-M365-GROUP';      resultStatus = 'Fail';         description = 'The group is a publicly visible Microsoft 365 group with static membership.' }
        @{ code = 'GRP-003-NOT-PUBLIC-M365-GROUP';  resultStatus = 'Pass';        description = 'The group is not a publicly visible, statically-membered Microsoft 365 group.' }
        @{ code = 'GRP-003-NO-GROUPS';              resultStatus = 'NotApplicable'; description = 'No Group entity was present in the evidence set.' }
        @{ code = 'GRP-003-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'Group evidence was not fully collected for this snapshot.' }
        @{ code = 'GRP-003-EVALUATOR-ERROR';        resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per collected Group entity. Fail if groupTypes contains Unified AND visibility equals Public AND groupTypes does not contain DynamicMembership; Pass otherwise. NotApplicable (single tenant-scoped result) only if zero groups exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPosturePublicM365GroupsControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review whether the affected groups genuinely need to be public. Since Microsoft 365 does not support restricting group creation to private groups only, consider limiting M365 group creation to trained administrators instead (see GRP-002).'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-management#group-settings'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. visibility and groupTypes confirmed present in the default GET /v1.0/groups response (no $select needed), re-fetched 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'GRP-003' }
    )

    baselineDependency = $null
}
