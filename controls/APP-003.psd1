@{
    <#
        VNext build order item 2, new-evidence phase (batch 6, 2026-08-08). Keys deliberately
        camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'APP-003'
    version     = '1.0.0'
    title       = 'App Registration with Non-Tier-0 Owner'
    description = 'For each Application entity, checks whether every owner holds an Active DirectoryRoleAssignment to a curated Tier-0 role -- inverse framing: Fails when the owner set includes anyone who does NOT hold a curated Tier-0 role.'
    rationale   = 'An owner can add credentials, register redirect URIs, change API permissions, or otherwise reconfigure the app registration they own -- an owner who is not themselves accountable, already-privileged is a governance gap: the app registration''s own trust boundary is only as strong as its least-privileged owner. Same framing as ENT-003 (enterprise applications) and AGT-017 (agent identity blueprints), applied here to the underlying Application entity.'
    severity    = 2
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('Application', 'DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per collected Application entity, regardless of owner count. NotApplicable (a single tenant-scoped result) only if the tenant has no app registrations at all; a specific application with zero owners produces its own per-application NotApplicable result rather than being folded into that tenant-scoped case.'

    reasonCodes = @(
        @{ code = 'APP-003-NON-TIER-ZERO-OWNER';  resultStatus = 'Fail';         description = 'At least one of the application''s owners has no Active assignment to any curated Tier-0 role.' }
        @{ code = 'APP-003-TIER-ZERO-OWNER-ONLY'; resultStatus = 'Pass';        description = 'Every one of the application''s owners has an Active assignment to a curated Tier-0 role.' }
        @{ code = 'APP-003-NO-OWNERS';            resultStatus = 'NotApplicable'; description = 'The application has no collected owner.' }
        @{ code = 'APP-003-NO-APPLICATIONS';      resultStatus = 'NotApplicable'; description = 'No Application entity was present in the evidence set.' }
        @{ code = 'APP-003-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'Application, DirectoryRole, or DirectoryRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'APP-003-EVALUATOR-ERROR';      resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per collected Application entity. An application with zero owners produces its own NotApplicable result (APP-003-NO-OWNERS). Otherwise: Fail if any owner lacks an Active Tier-0 DirectoryRoleAssignment, Pass if every owner has one. The overall tenant-scoped NotApplicable (APP-003-NO-APPLICATIONS) applies only when zero applications exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureAppRegistrationOwnerTierControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Add a Tier-0-role-holding owner, or transfer ownership entirely to already-privileged, accountable principals. Remove owners who do not hold Tier-0 privilege from an app registration capable of holding client secrets/certificates and API permissions.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/application-list-owners?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity (consolidates EF-REG-007 "Owners"), not a port of EntraFalcon''s own source logic. Owners collected via GET /v1.0/applications/{id}/owners, the same fetch CollectApplications.ps1 already added for APP-003 (2026-08-08, VNext build order item 2 batch 6, the new-evidence phase).'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'APP-003' }
    )

    baselineDependency = $null
}
