@{
    <#
        VNext build order item 2, new-evidence phase (the "Extensive API Privileges" architecture-
        fork item, resolved 2026-08-08). Thin wrapper over Get-EntraPostureExtensiveApiPrivilege
        ControlResult (ExtensiveApiPrivilege.ps1) -- see that function's own header comment for
        the shared logic every sibling control (ENT-004/005/009/010, AGT-002/003/006/007,
        MAI-001) reuses. Keys deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'MAI-001'
    version     = '1.0.0'
    title       = 'Managed Identities with API Privileges'
    description = 'For each ManagedIdentity entity, checks whether it holds a Microsoft-Graph-scoped application permission from this project''s curated dangerous-permission list. No foreign/internal split and no delegated-permission sibling control -- a managed identity is inherently tenant-local and can only ever hold application permissions.'
    rationale   = 'A dangerous application permission grants a standing, credential-free path to escalate privilege or take over the directory outright, independent of any explicit role assignment -- a managed identity holding one is a real risk if the Azure resource it''s attached to, or anything with rights to use it, is ever compromised.'
    severity    = 2
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ManagedIdentity', 'ServicePrincipalApiPermissions')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
        @{ scope = 'Directory.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per collected ManagedIdentity entity. NotApplicable (a single tenant-scoped result) if no ManagedIdentity entity was present at all.'

    reasonCodes = @(
        @{ code = 'MAI-001-EXTENSIVE-PRIVILEGE';    resultStatus = 'Fail';         description = 'The managed identity holds a Microsoft-Graph-scoped application permission from this project''s curated dangerous-permission list.' }
        @{ code = 'MAI-001-NO-EXTENSIVE-PRIVILEGE'; resultStatus = 'Pass';        description = 'The managed identity holds no application permission from this project''s curated dangerous-permission list.' }
        @{ code = 'MAI-001-NO-CANDIDATES';          resultStatus = 'NotApplicable'; description = 'No ManagedIdentity entity was present in the evidence set.' }
        @{ code = 'MAI-001-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'ManagedIdentity or ServicePrincipalApiPermissions evidence was not fully collected for this snapshot.' }
        @{ code = 'MAI-001-EVALUATOR-ERROR';        resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per collected ManagedIdentity entity. Fail if it holds at least one Microsoft-Graph-scoped application permission from the curated dangerous-permission list, Pass otherwise. NotApplicable (single tenant-scoped result) only if zero managed identities exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureManagedIdentityExtensiveApiPrivilegeControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review why the managed identity was granted a dangerous application permission. Remove the grant; if ongoing access is required, scope it to the narrowest permission that satisfies the actual integration need.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/permissions-reference'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic or its full multi-tier risk-scoring system. See ENT-004.psd1''s own provenance notes for the shared curation methodology and the architecture-fork resolution this control family is part of. No-foreign-split population sizing matches MAI-002/003''s own already-established precedent.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'MAI-001' }
    )

    baselineDependency = $null
}
