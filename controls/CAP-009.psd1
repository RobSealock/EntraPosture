@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08). See
        CAP-001.psd1's header comment for shared context. Keys deliberately camelCase.
    #>
    controlId   = 'CAP-009'
    version     = '1.0.0'
    title       = 'MFA Not Enforced'
    description = 'Checks whether any enabled Conditional Access policy requires MFA for all users tenant-wide (conditions.users.includeUsers contains All, with an MFA-satisfying grant).'
    rationale   = 'Distinct from PRIV-001/CA-001 (Tier-0 administrator MFA coverage specifically): this checks the broadest possible population. A tenant with strong admin-only MFA coverage can still leave every non-admin user unprotected by any MFA requirement at all.'
    severity    = 3
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ConditionalAccessPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable -- a single tenant-scoped result.'

    reasonCodes = @(
        @{ code = 'CAP-009-MFA-ENFORCED';     resultStatus = 'Pass';        description = 'At least one enabled policy requires MFA for all users.' }
        @{ code = 'CAP-009-MFA-NOT-ENFORCED'; resultStatus = 'Fail';         description = 'No enabled policy requires MFA for all users tenant-wide.' }
        @{ code = 'CAP-009-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'ConditionalAccessPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'CAP-009-EVALUATOR-ERROR';        resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Single tenant-scoped result. Pass if at least one enabled policy has includeUsers containing All with builtInControls containing mfa or a set authenticationStrengthId; Fail otherwise. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureBroadMfaEnforcementControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Create an enabled Conditional Access policy scoping includeUsers to All with an MFA grant control (excluding break-glass accounts per standard practice).'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'CAP-009' }
    )

    baselineDependency = $null
}
