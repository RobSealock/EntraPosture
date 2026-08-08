@{
    <#
        VNext build order item 2, new-evidence phase (batch 6, 2026-08-08). Keys deliberately
        camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'ENT-003'
    version     = '1.0.0'
    title       = 'Enterprise Applications with Non-Tier-0 Owner'
    description = 'For each ServicePrincipal entity, checks whether every owner holds an Active DirectoryRoleAssignment to a curated Tier-0 role -- inverse framing: Fails when the owner set includes anyone who does NOT hold a curated Tier-0 role.'
    rationale   = 'An owner can add credentials, change API permissions, or otherwise reconfigure the enterprise application they own -- an owner who is not themselves accountable, already-privileged is a governance gap: the application''s own trust boundary is only as strong as its least-privileged owner. Same framing as AGT-017 (agent identity blueprints), generalized here to every ordinary enterprise application.'
    severity    = 2
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ServicePrincipal', 'DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per collected ServicePrincipal entity, regardless of owner count. NotApplicable (a single tenant-scoped result) only if the tenant has no service principals at all; a specific service principal with zero owners produces its own per-principal NotApplicable result rather than being folded into that tenant-scoped case.'

    reasonCodes = @(
        @{ code = 'ENT-003-NON-TIER-ZERO-OWNER';   resultStatus = 'Fail';         description = 'At least one of the service principal''s owners has no Active assignment to any curated Tier-0 role.' }
        @{ code = 'ENT-003-TIER-ZERO-OWNER-ONLY';  resultStatus = 'Pass';        description = 'Every one of the service principal''s owners has an Active assignment to a curated Tier-0 role.' }
        @{ code = 'ENT-003-NO-OWNERS';             resultStatus = 'NotApplicable'; description = 'The service principal has no collected owner.' }
        @{ code = 'ENT-003-NO-SERVICE-PRINCIPALS'; resultStatus = 'NotApplicable'; description = 'No ServicePrincipal entity was present in the evidence set.' }
        @{ code = 'ENT-003-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'ServicePrincipal, DirectoryRole, or DirectoryRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'ENT-003-EVALUATOR-ERROR';       resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per collected ServicePrincipal entity. A principal with zero owners produces its own NotApplicable result (ENT-003-NO-OWNERS). Otherwise: Fail if any owner lacks an Active Tier-0 DirectoryRoleAssignment, Pass if every owner has one. The overall tenant-scoped NotApplicable (ENT-003-NO-SERVICE-PRINCIPALS) applies only when zero service principals exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureEnterpriseAppOwnerTierControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Add a Tier-0-role-holding owner, or transfer ownership entirely to already-privileged, accountable principals. Remove owners who do not hold Tier-0 privilege from an enterprise application capable of holding client credentials and API permissions.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-owners?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity (consolidates EF-EAP-007 "Owners"), not a port of EntraFalcon''s own source logic. Owners collected via GET /v1.0/servicePrincipals/{id}/owners, added to CollectServicePrincipals.ps1 alongside ENT-008''s ownedObjects fetch (2026-08-08, VNext build order item 2 batch 6, the new-evidence phase).'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'ENT-003' }
    )

    baselineDependency = $null
}
