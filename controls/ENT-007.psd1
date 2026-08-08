@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08, batch
        4). Keys deliberately camelCase.
    #>
    controlId   = 'ENT-007'
    version     = '1.0.0'
    title       = 'Foreign Enterprise Applications with Azure Roles'
    description = 'For each ServicePrincipal entity confirmed foreign, checks whether it holds any Azure RBAC role assignment.'
    rationale   = 'Same cross-tenant blast-radius concern as ENT-006, applied to the Azure RBAC authorization plane -- a foreign application with any Azure role assignment can act against Azure resources without this tenant''s own admin consent review ever having considered that specific application.'
    severity    = 3
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ServicePrincipal', 'AzureRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per ServicePrincipal entity confirmed foreign. NotApplicable (a single tenant-scoped result) if no ServicePrincipal was confirmed foreign at all.'

    reasonCodes = @(
        @{ code = 'ENT-007-FOREIGN-AZURE-ROLE';            resultStatus = 'Fail';         description = 'The foreign service principal holds at least one Azure RBAC role assignment.' }
        @{ code = 'ENT-007-NO-AZURE-ROLE';                 resultStatus = 'Pass';        description = 'The foreign service principal holds no Azure RBAC role assignment.' }
        @{ code = 'ENT-007-NO-FOREIGN-SERVICE-PRINCIPALS'; resultStatus = 'NotApplicable'; description = 'No ServicePrincipal entity was confirmed foreign in the evidence set.' }
        @{ code = 'ENT-007-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'ServicePrincipal or AzureRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'ENT-007-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per ServicePrincipal entity confirmed foreign. Fail if any AzureRoleAssignment entity''s properties.principalId matches it, Pass otherwise. NotApplicable (single tenant-scoped result) only if zero foreign service principals exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureForeignServicePrincipalAzureRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review why a foreign-owned application was granted an Azure RBAC role. Remove the assignment unless a specific, reviewed business need requires it.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'ENT-007' }
    )

    baselineDependency = $null
}
