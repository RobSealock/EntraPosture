@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08). See
        CAP-001.psd1's header comment for shared context. Keys deliberately camelCase.
    #>
    controlId   = 'CAP-003'
    version     = '1.0.0'
    title       = 'Legacy Authentication Not Blocked'
    description = 'Checks whether any enabled Conditional Access policy blocks legacy authentication clients (conditions.clientAppTypes contains exchangeActiveSync or other, with a block grant control).'
    rationale   = 'Legacy authentication protocols cannot enforce modern authentication controls like MFA -- Microsoft has documented legacy auth as one of the highest-volume attack vectors for credential-stuffing and password-spray attacks for years, and recommends blocking it outright rather than merely restricting it.'
    severity    = 3
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ConditionalAccessPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable -- a single tenant-scoped result.'

    reasonCodes = @(
        @{ code = 'CAP-003-LEGACY-AUTH-BLOCKED';   resultStatus = 'Pass';        description = 'At least one enabled policy blocks legacy authentication clients.' }
        @{ code = 'CAP-003-LEGACY-AUTH-UNBLOCKED'; resultStatus = 'Fail';         description = 'No enabled policy blocks legacy authentication clients.' }
        @{ code = 'CAP-003-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'ConditionalAccessPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'CAP-003-EVALUATOR-ERROR';        resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Single tenant-scoped result. Pass if at least one enabled policy has clientAppTypes containing exchangeActiveSync or other with a block grant; Fail otherwise. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureLegacyAuthenticationBlockControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Create an enabled Conditional Access policy scoping clientAppTypes to exchangeActiveSync and other with a block grant control.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. clientAppTypes literal values confirmed live against the conditionalAccessConditionSet Graph reference page, re-fetched 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'CAP-003' }
    )

    baselineDependency = $null
}
