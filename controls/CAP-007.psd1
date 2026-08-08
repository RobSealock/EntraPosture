@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08). See
        CAP-001.psd1's header comment for shared context. Keys deliberately camelCase.
    #>
    controlId   = 'CAP-007'
    version     = '1.0.0'
    title       = 'Sign-In Risk Not Managed'
    description = 'Checks whether any enabled Conditional Access policy acts on sign-in risk level (conditions.signInRiskLevels non-empty, with a non-trivial grant control).'
    rationale   = 'Entra ID Protection surfaces a sign-in risk signal (impossible travel, anonymous IP, malware-linked IP, etc.) that has no security effect at all unless a Conditional Access policy actually consumes it -- collecting the signal without acting on it gives no protection.'
    severity    = 2
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ConditionalAccessPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable -- a single tenant-scoped result.'

    reasonCodes = @(
        @{ code = 'CAP-007-SIGN-IN-RISK-MANAGED';     resultStatus = 'Pass';        description = 'At least one enabled policy acts on sign-in risk level.' }
        @{ code = 'CAP-007-SIGN-IN-RISK-NOT-MANAGED'; resultStatus = 'Fail';         description = 'No enabled policy acts on sign-in risk level.' }
        @{ code = 'CAP-007-EVIDENCE-NOT-COLLECTED';   resultStatus = 'NotEvaluated'; description = 'ConditionalAccessPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'CAP-007-EVALUATOR-ERROR';          resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Single tenant-scoped result. Pass if at least one enabled policy has signInRiskLevels non-empty with a non-trivial grant; Fail otherwise. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureSignInRiskManagementControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Create an enabled Conditional Access policy scoping signInRiskLevels (e.g. medium and high) with an appropriate grant or block control -- requires Entra ID Protection (P2) licensing.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'CAP-007' }
    )

    baselineDependency = $null
}
