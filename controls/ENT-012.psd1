@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08, batch
        4). Keys deliberately camelCase.
    #>
    controlId   = 'ENT-012'
    version     = '1.0.0'
    title       = 'Internal Enterprise Applications with Privileged Azure Roles'
    description = 'For each ServicePrincipal entity confirmed internal (non-foreign), checks whether it holds any Azure RBAC role assignment.'
    rationale   = 'Same concern as ENT-011, applied to the Azure RBAC authorization plane.'
    severity    = 2
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ServicePrincipal', 'AzureRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per ServicePrincipal entity confirmed internal (non-foreign). NotApplicable (a single tenant-scoped result) if no ServicePrincipal entity exists at all.'

    reasonCodes = @(
        @{ code = 'ENT-012-INTERNAL-AZURE-ROLE';            resultStatus = 'Fail';         description = 'The internal service principal holds at least one Azure RBAC role assignment.' }
        @{ code = 'ENT-012-NO-AZURE-ROLE';                  resultStatus = 'Pass';        description = 'The internal service principal holds no Azure RBAC role assignment.' }
        @{ code = 'ENT-012-NO-INTERNAL-SERVICE-PRINCIPALS'; resultStatus = 'NotApplicable'; description = 'No ServicePrincipal entity was present in the evidence set.' }
        @{ code = 'ENT-012-EVIDENCE-NOT-COLLECTED';         resultStatus = 'NotEvaluated'; description = 'ServicePrincipal or AzureRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'ENT-012-EVALUATOR-ERROR';                resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per ServicePrincipal entity confirmed internal. Fail if any AzureRoleAssignment entity''s properties.principalId matches it, Pass otherwise. NotApplicable (single tenant-scoped result) only if zero service principals exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureInternalServicePrincipalAzureRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review the Azure RBAC role assignment; remove it or narrow its scope if the application does not require it.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'ENT-012' }
    )

    baselineDependency = $null
}
