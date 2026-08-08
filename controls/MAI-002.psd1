@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08). Keys
        deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'MAI-002'
    version     = '1.0.0'
    title       = 'Managed Identities with Privileged Entra ID Roles'
    description = 'For each ManagedIdentity entity, checks whether it holds an Active DirectoryRoleAssignment to a curated Tier-0 role.'
    rationale   = 'A managed identity has no interactive owner and no MFA/Conditional Access surface of its own -- a compromised resource whose managed identity holds Tier-0 privilege gives an attacker that privilege with no additional authentication barrier at all.'
    severity    = 2
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ManagedIdentity', 'DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per collected ManagedIdentity entity. NotApplicable (a single tenant-scoped result) if the tenant has no managed identities at all.'

    reasonCodes = @(
        @{ code = 'MAI-002-TIER-ZERO-ROLE';        resultStatus = 'Fail';         description = 'The managed identity holds an Active assignment to a curated Tier-0 role.' }
        @{ code = 'MAI-002-NO-TIER-ZERO-ROLE';      resultStatus = 'Pass';        description = 'The managed identity holds no Active assignment to any curated Tier-0 role.' }
        @{ code = 'MAI-002-NO-MANAGED-IDENTITIES';  resultStatus = 'NotApplicable'; description = 'No ManagedIdentity entity was present in the evidence set.' }
        @{ code = 'MAI-002-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'ManagedIdentity, DirectoryRole, or DirectoryRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'MAI-002-EVALUATOR-ERROR';        resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per collected ManagedIdentity entity. Fail if an Active DirectoryRoleAssignment to a curated Tier-0 role exists for it, Pass otherwise. NotApplicable (single tenant-scoped result) only if zero managed identities exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureManagedIdentityEntraRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Remove the standing Tier-0 role assignment from the managed identity, or replace it with a narrower, custom-scoped role that grants only what the underlying resource actually needs.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. Unlike the AGT-*/ENT-* families, managed identities have no foreign/internal split (a managed identity is inherently tenant-scoped by Microsoft''s own design), so this control has a single population, the same shape AGT-008 applies to internal agent identities.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'MAI-002' }
    )

    baselineDependency = $null
}
