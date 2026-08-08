@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08, batch
        4). Keys deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'ENT-006'
    version     = '1.0.0'
    title       = 'Foreign Enterprise Applications with Entra ID Roles'
    description = 'For each ServicePrincipal entity confirmed foreign (appOwnerOrganizationId differs from this tenant), checks whether it holds an Active DirectoryRoleAssignment to a curated Tier-0 role.'
    rationale   = 'A service principal representing an application your tenant does not own is, functionally, a third party''s principal operating inside your directory -- the same cross-tenant blast-radius concern XTA-001/002/AGT-004 already apply, applied here to ordinary enterprise applications (the largest, most common foreign-principal population in most tenants).'
    severity    = 3
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ServicePrincipal', 'DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per ServicePrincipal entity confirmed foreign. NotApplicable (a single tenant-scoped result) if no ServicePrincipal was confirmed foreign at all.'

    reasonCodes = @(
        @{ code = 'ENT-006-FOREIGN-TIER-ZERO-ROLE';        resultStatus = 'Fail';         description = 'The foreign service principal holds an Active assignment to a curated Tier-0 role.' }
        @{ code = 'ENT-006-NO-TIER-ZERO-ROLE';             resultStatus = 'Pass';        description = 'The foreign service principal holds no Active assignment to any curated Tier-0 role.' }
        @{ code = 'ENT-006-NO-FOREIGN-SERVICE-PRINCIPALS'; resultStatus = 'NotApplicable'; description = 'No ServicePrincipal entity was confirmed foreign in the evidence set.' }
        @{ code = 'ENT-006-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'ServicePrincipal, DirectoryRole, or DirectoryRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'ENT-006-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per ServicePrincipal entity confirmed foreign. Fail if an Active DirectoryRoleAssignment to a curated Tier-0 role exists for it, Pass otherwise. NotApplicable (single tenant-scoped result) only if zero foreign service principals exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureForeignServicePrincipalEntraRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review why a foreign-owned application was granted a Tier-0 role. Remove the standing assignment; if ongoing access is required, scope it to a narrower, non-Tier-0 role.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. appOwnerOrganizationId confirmed present on the default, unfiltered GET /v1.0/servicePrincipals response (re-verified 2026-08-08); unlike the AGT-* agent-identity family, this is a single-hop check directly on ServicePrincipal, no blueprint-principal indirection needed.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'ENT-006' }
    )

    baselineDependency = $null
}
