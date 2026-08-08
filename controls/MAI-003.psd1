@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08). Keys
        deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'MAI-003'
    version     = '1.0.0'
    title       = 'Managed Identities with Privileged Azure Roles'
    description = 'For each ManagedIdentity entity, checks whether it holds any Azure RBAC role assignment.'
    rationale   = 'Same concern as MAI-002, applied to the Azure RBAC authorization plane -- managed identities are frequently granted Azure roles directly (their primary use case), so this is the more commonly-populated of the two, not a hypothetical.'
    severity    = 2
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ManagedIdentity', 'AzureRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per collected ManagedIdentity entity. NotApplicable (a single tenant-scoped result) if the tenant has no managed identities at all.'

    reasonCodes = @(
        @{ code = 'MAI-003-AZURE-ROLE';             resultStatus = 'Fail';         description = 'The managed identity holds at least one Azure RBAC role assignment.' }
        @{ code = 'MAI-003-NO-AZURE-ROLE';          resultStatus = 'Pass';        description = 'The managed identity holds no Azure RBAC role assignment.' }
        @{ code = 'MAI-003-NO-MANAGED-IDENTITIES';  resultStatus = 'NotApplicable'; description = 'No ManagedIdentity entity was present in the evidence set.' }
        @{ code = 'MAI-003-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'ManagedIdentity or AzureRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'MAI-003-EVALUATOR-ERROR';        resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per collected ManagedIdentity entity. Fail if any AzureRoleAssignment entity''s properties.principalId matches it, Pass otherwise. NotApplicable (single tenant-scoped result) only if zero managed identities exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureManagedIdentityAzureRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review the Azure RBAC role assignment; replace an overly broad role (e.g. Owner/Contributor at a wide scope) with the narrowest built-in or custom role the underlying resource actually needs.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'MAI-003' }
    )

    baselineDependency = $null
}
