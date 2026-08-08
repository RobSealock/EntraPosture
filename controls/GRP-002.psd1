@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Reuses the
        GroupSetting evidence/collector infrastructure COL-003 already built. Keys deliberately
        camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'GRP-002'
    version     = '1.0.0'
    title       = 'M365 Group Creation Not Restricted'
    description = 'Checks the tenant''s Group.Unified group settings for EnableGroupCreation. Fails if true (or no customized Group.Unified settings object exists -- Microsoft''s own documented default is true); passes if explicitly false.'
    rationale   = 'Unrestricted Microsoft 365 group creation leads to group sprawl with no governance -- every M365 group provisions a SharePoint site, Teams channel, and shared mailbox by default, each a potential data-exposure surface with no admin review at creation time.'
    severity    = 1
    category    = 'Groups'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('GroupSetting')
    requiredPermissions     = @(
        @{ scope = 'GroupSettings.Read.All'; confirmed = $true }
    )

    applicability = 'A single tenant-scoped result. Always evaluated once GroupSettings evidence has been collected.'

    reasonCodes = @(
        @{ code = 'GRP-002-GROUP-CREATION-UNRESTRICTED'; resultStatus = 'Fail';         description = 'M365 group creation is not restricted, or no customized Group.Unified settings object exists (documented default is unrestricted).' }
        @{ code = 'GRP-002-GROUP-CREATION-RESTRICTED';   resultStatus = 'Pass';        description = 'M365 group creation is restricted to specific users/roles.' }
        @{ code = 'GRP-002-EVIDENCE-NOT-COLLECTED';      resultStatus = 'NotEvaluated'; description = 'GroupSetting evidence was not fully collected for this snapshot.' }
        @{ code = 'GRP-002-EVALUATOR-ERROR';             resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Exactly one tenant-scoped result. Fail unless a Group.Unified groupSetting object exists and explicitly sets EnableGroupCreation to false -- no such object at all defaults to Fail (the opposite absence-handling direction from COL-003''s own AllowGuestsToBeGroupOwner check, since this field''s own documented default is unrestricted, not restricted). NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureM365GroupCreationRestrictionControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Restrict Microsoft 365 group creation to a designated group of trained users or administrators (set EnableGroupCreation to false and optionally GroupCreationAllowedGroupId to an approved group).'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/group-list-settings?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-groups'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. EnableGroupCreation''s documented default (true, unrestricted) confirmed against live documentation, re-fetched 2026-08-08 -- a real absence-handling direction independently verified, not assumed.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'GRP-002' }
    )

    baselineDependency = $null
}
