@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08). See
        CAP-001.psd1's header comment for shared context. Keys deliberately camelCase.
    #>
    controlId   = 'CAP-002'
    version     = '1.0.0'
    title       = 'Registration of Security Info Not Restricted'
    description = 'Checks whether any enabled Conditional Access policy governs the "register security info" user action (conditions.applications.includeUserActions contains urn:user:registersecurityinfo) with a non-trivial grant control.'
    rationale   = 'Security-info registration (adding a new MFA method) is a sensitive self-service action -- an attacker who compromises a session can register their own MFA method to establish persistent access unless this action itself is governed by Conditional Access.'
    severity    = 2
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ConditionalAccessPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable -- a single tenant-scoped result.'

    reasonCodes = @(
        @{ code = 'CAP-002-SECURITY-INFO-REGISTRATION-RESTRICTED';   resultStatus = 'Pass';        description = 'At least one enabled policy governs security info registration with a non-trivial grant.' }
        @{ code = 'CAP-002-SECURITY-INFO-REGISTRATION-UNRESTRICTED'; resultStatus = 'Fail';         description = 'No enabled policy governs the register security info user action.' }
        @{ code = 'CAP-002-EVIDENCE-NOT-COLLECTED';                  resultStatus = 'NotEvaluated'; description = 'ConditionalAccessPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'CAP-002-EVALUATOR-ERROR';                         resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Single tenant-scoped result. Pass if at least one enabled policy targets urn:user:registersecurityinfo with a non-empty grant; Fail otherwise. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureSecurityInfoRegistrationRestrictionControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Create an enabled Conditional Access policy targeting the register security info user action with an appropriate grant control (e.g. requiring a trusted location or compliant device).'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. includeUserActions literal value confirmed live against the conditionalAccessApplications Graph reference page, re-fetched 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'CAP-002' }
    )

    baselineDependency = $null
}
