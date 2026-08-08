@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08). See
        CAP-001.psd1's header comment for shared context. Keys deliberately camelCase.
    #>
    controlId   = 'CAP-008'
    version     = '1.0.0'
    title       = 'User Risk Not Managed'
    description = 'Checks whether any enabled Conditional Access policy acts on user risk level (conditions.userRiskLevels non-empty, with a non-trivial grant control).'
    rationale   = 'Same as CAP-007, for the user-risk signal (leaked credentials, confirmed-compromised account, etc.) instead of sign-in risk -- a distinct Entra ID Protection detection that also has no security effect unless a policy consumes it.'
    severity    = 2
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ConditionalAccessPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable -- a single tenant-scoped result.'

    reasonCodes = @(
        @{ code = 'CAP-008-USER-RISK-MANAGED';     resultStatus = 'Pass';        description = 'At least one enabled policy acts on user risk level.' }
        @{ code = 'CAP-008-USER-RISK-NOT-MANAGED'; resultStatus = 'Fail';         description = 'No enabled policy acts on user risk level.' }
        @{ code = 'CAP-008-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'ConditionalAccessPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'CAP-008-EVALUATOR-ERROR';        resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Single tenant-scoped result. Pass if at least one enabled policy has userRiskLevels non-empty with a non-trivial grant; Fail otherwise. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureUserRiskManagementControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Create an enabled Conditional Access policy scoping userRiskLevels (e.g. high) with an appropriate grant or block control -- requires Entra ID Protection (P2) licensing.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'CAP-008' }
    )

    baselineDependency = $null
}
