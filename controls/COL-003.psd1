@{
    <#
        VNext build order item 2, new-evidence phase (batch 7, 2026-08-08). New GroupSettings
        collector -- see CollectGroupSettings.ps1's own header comment for why this needed a new
        collector rather than a field extension to an already-called endpoint. Keys deliberately
        camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'COL-003'
    version     = '1.0.0'
    title       = 'Guests Allowed to Own M365 Groups'
    description = 'Checks the tenant''s Group.Unified group settings for the AllowGuestsToBeGroupOwner value. Fails if explicitly set to true; Passes if explicitly set to false or if the tenant has never customized Group.Unified away from Microsoft''s own documented default (false).'
    rationale   = 'A guest (external, unmanaged-identity) user who owns a Microsoft 365 group can add/remove members, change group settings, and in many tenant configurations provision the group''s own Team/SharePoint site -- ownership rights extended to an identity this tenant does not control and cannot fully govern.'
    severity    = 1
    category    = 'External Collaboration'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('GroupSetting')
    requiredPermissions     = @(
        @{ scope = 'GroupSettings.Read.All'; confirmed = $true }
    )

    applicability = 'A single tenant-scoped result. Always evaluated once GroupSettings evidence has been collected -- an empty GroupSetting entity set is a real, meaningful outcome (the tenant has never customized Group.Unified, so Microsoft''s documented default applies), not a NotApplicable case.'

    reasonCodes = @(
        @{ code = 'COL-003-GUESTS-ALLOWED-GROUP-OWNER';      resultStatus = 'Fail';         description = 'The tenant''s Group.Unified settings explicitly set AllowGuestsToBeGroupOwner to true.' }
        @{ code = 'COL-003-GUESTS-NOT-ALLOWED-GROUP-OWNER';  resultStatus = 'Pass';        description = 'The tenant''s Group.Unified settings explicitly set AllowGuestsToBeGroupOwner to false.' }
        @{ code = 'COL-003-DEFAULT-GUESTS-NOT-ALLOWED';      resultStatus = 'Pass';        description = 'No Group.Unified group settings object exists for this tenant; Microsoft''s documented template default (AllowGuestsToBeGroupOwner = false) applies.' }
        @{ code = 'COL-003-EVIDENCE-NOT-COLLECTED';          resultStatus = 'NotEvaluated'; description = 'GroupSetting evidence was not fully collected for this snapshot.' }
        @{ code = 'COL-003-EVALUATOR-ERROR';                 resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Exactly one tenant-scoped result. Fail only if a Group.Unified groupSetting object exists and explicitly sets AllowGuestsToBeGroupOwner to true; Pass if it exists and sets it to false, or if no such object exists at all (the documented default, confirmed against live Microsoft Graph documentation, not assumed). NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureGuestGroupOwnershipControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Set AllowGuestsToBeGroupOwner to false on the tenant''s Group.Unified settings object (create the settings object from the Group.Unified template first if none exists), and review/remove any guest user currently holding group ownership.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/group-list-settings?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/groupsetting?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity (a new, no-README-counterpart finding derived directly from EntraFalcon''s check_Tenant.psm1, not a port of its source logic). AllowGuestsToBeGroupOwner''s presence and shape (settingValue name/value pair inside the Group.Unified groupSetting''s values array) and its documented default (false) both confirmed directly against live Microsoft Graph documentation, re-fetched 2026-08-08, including the reference page''s own worked example response.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'COL-003' }
    )

    baselineDependency = $null
}
