@{
    <#
        First of the "zero new evidence" matrix-row slice (VNext build order item 2, resumed
        2026-08-08 per the project owner's explicit request to prioritize high-confidence rows
        needing no new collector). Control ID/title reused from 15-feature-parity-matrix.md
        section 3.3's canonical EntraFalcon-derived registry for tracking continuity; independently
        authored against this project's own ConditionalAccessPolicy evidence, not a port. Keys
        deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'CAP-001'
    version     = '1.0.0'
    title       = 'Device Code Flow Not Restricted'
    description = 'Checks whether any enabled Conditional Access policy blocks sign-ins using the device code authentication flow (conditions.authenticationFlows.transferMethods = deviceCodeFlow, with a block grant control).'
    rationale   = 'The device code flow is a common phishing/social-engineering vector (an attacker tricks a user into approving a device-code sign-in on the attacker''s behalf) -- Microsoft documents it as a flow worth restricting via Conditional Access for tenants that do not use it operationally.'
    severity    = 2
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ConditionalAccessPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable -- a single tenant-scoped result evaluated against every enabled ConditionalAccessPolicy entity in the snapshot.'

    reasonCodes = @(
        @{ code = 'CAP-001-DEVICE-CODE-FLOW-BLOCKED';      resultStatus = 'Pass';        description = 'At least one enabled policy blocks the device code authentication flow.' }
        @{ code = 'CAP-001-DEVICE-CODE-FLOW-UNRESTRICTED'; resultStatus = 'Fail';         description = 'No enabled policy blocks the device code authentication flow.' }
        @{ code = 'CAP-001-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'ConditionalAccessPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'CAP-001-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Single tenant-scoped result. Pass if at least one enabled policy has authenticationFlowTransferMethods = deviceCodeFlow and a block grant control; Fail otherwise. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureDeviceCodeFlowRestrictionControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Create an enabled Conditional Access policy scoping conditions.authenticationFlows.transferMethods to deviceCodeFlow with a block grant control, unless device code flow is operationally required.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessauthenticationflows?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. authenticationFlowTransferMethods literal value "deviceCodeFlow" confirmed live against the conditionalAccessAuthenticationFlows Graph reference page, re-fetched 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'CAP-001' }
    )

    baselineDependency = $null
}
