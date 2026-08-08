@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08, batch
        4). Keys deliberately camelCase.
    #>
    controlId   = 'USR-008'
    version     = '1.0.0'
    title       = 'Hybrid Users with Tier-0 Azure Roles'
    description = 'For each hybrid-synced User entity (onPremisesSyncEnabled=true), checks whether it holds any Azure RBAC role assignment.'
    rationale   = 'Same concern as USR-007, applied to the Azure RBAC authorization plane.'
    severity    = 2
    category    = 'Identity'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('User', 'AzureRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'User.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per User entity with onPremisesSyncEnabled=true. NotApplicable (a single tenant-scoped result) if the tenant has no hybrid-synced users at all.'

    reasonCodes = @(
        @{ code = 'USR-008-HYBRID-AZURE-ROLE';      resultStatus = 'Fail';         description = 'The hybrid-synced user holds at least one Azure RBAC role assignment.' }
        @{ code = 'USR-008-NO-AZURE-ROLE';          resultStatus = 'Pass';        description = 'The hybrid-synced user holds no Azure RBAC role assignment.' }
        @{ code = 'USR-008-NO-HYBRID-USERS';        resultStatus = 'NotApplicable'; description = 'No User entity with onPremisesSyncEnabled=true was present in the evidence set.' }
        @{ code = 'USR-008-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'User or AzureRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'USR-008-EVALUATOR-ERROR';        resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per hybrid-synced User entity. Fail if any AzureRoleAssignment entity''s properties.principalId matches it, Pass otherwise. NotApplicable (single tenant-scoped result) only if zero hybrid-synced users exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureHybridUserAzureRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Provision a dedicated cloud-only account for Tier-0 Azure administration and remove the role assignment from the hybrid-synced account.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'USR-008' }
    )

    baselineDependency = $null
}
