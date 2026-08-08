@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08). See
        CAP-001.psd1's header comment for shared context. Keys deliberately camelCase.
    #>
    controlId   = 'CAP-006'
    version     = '1.0.0'
    title       = 'Combined Risk Policy Not Configured'
    description = 'Checks whether any single enabled Conditional Access policy acts on both sign-in risk and user risk together (both conditions.signInRiskLevels and conditions.userRiskLevels non-empty on the same policy).'
    rationale   = 'Distinct from CAP-007/CAP-008 (which each check that a risk type is managed by any policy at all): a tenant that only manages the two risk dimensions through separate, independently-scoped policies can develop coverage gaps at the boundary (e.g. a user with both a risky sign-in AND a compromised-account signal matched by neither policy''s exact scope) that a single combined-risk policy avoids.'
    severity    = 2
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ConditionalAccessPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable -- a single tenant-scoped result.'

    reasonCodes = @(
        @{ code = 'CAP-006-COMBINED-RISK-POLICY-CONFIGURED';     resultStatus = 'Pass';        description = 'At least one enabled policy acts on both sign-in risk and user risk together.' }
        @{ code = 'CAP-006-COMBINED-RISK-POLICY-NOT-CONFIGURED'; resultStatus = 'Fail';         description = 'No single enabled policy acts on both sign-in risk and user risk together.' }
        @{ code = 'CAP-006-EVIDENCE-NOT-COLLECTED';              resultStatus = 'NotEvaluated'; description = 'ConditionalAccessPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'CAP-006-EVALUATOR-ERROR';                     resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Single tenant-scoped result. Pass if at least one enabled policy has both signInRiskLevels and userRiskLevels non-empty with a non-trivial grant; Fail otherwise. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureCombinedRiskPolicyControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Create (or extend an existing) enabled Conditional Access policy scoping both signInRiskLevels and userRiskLevels together with an appropriate grant control.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. This project''s own interpretation of "combined risk policy" as one policy scoping both risk dimensions together, stated as such -- the source finding''s own check logic was not read for this pass.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'CAP-006' }
    )

    baselineDependency = $null
}
