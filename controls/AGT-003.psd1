@{
    <#
        VNext build order item 2, new-evidence phase (the "Extensive API Privileges" architecture-
        fork item, resolved 2026-08-08). Thin wrapper over Get-EntraPostureExtensiveApiPrivilege
        ControlResult (ExtensiveApiPrivilege.ps1) -- see that function's own header comment for
        the shared logic every sibling control (ENT-004/005/009/010, AGT-002/003/006/007,
        MAI-001) reuses. Keys deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'AGT-003'
    version     = '1.0.0'
    title       = 'Foreign Agent Identities with Extensive API Privileges (Delegated)'
    description = 'For each AgentIdentity entity confirmed foreign, checks whether it holds a Microsoft-Graph-scoped delegated permission from this project''s curated dangerous-permission list.'
    rationale   = 'An agent identity your tenant does not own, holding a standing delegated permission capable of directory-wide privilege escalation or takeover, is a severe cross-tenant blast-radius concern -- the same reasoning ENT-005 applies to ordinary enterprise applications, applied here to the first-class agent identity population.'
    severity    = 2
    category    = 'Agent Identities'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AgentIdentity', 'AgentIdentityBlueprintPrincipal', 'ServicePrincipalApiPermissions')
    requiredPermissions     = @(
        @{ scope = 'AgentIdentity.Read.All'; confirmed = $true }
        @{ scope = 'AgentIdentityBlueprintPrincipal.Read.All'; confirmed = $true }
        @{ scope = 'Application.Read.All'; confirmed = $true }
        @{ scope = 'Directory.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per AgentIdentity entity confirmed foreign. NotApplicable (a single tenant-scoped result) if no AgentIdentity was confirmed foreign at all.'

    reasonCodes = @(
        @{ code = 'AGT-003-EXTENSIVE-PRIVILEGE';    resultStatus = 'Fail';         description = 'The foreign agent identity holds a Microsoft-Graph-scoped delegated permission from this project''s curated dangerous-permission list.' }
        @{ code = 'AGT-003-NO-EXTENSIVE-PRIVILEGE'; resultStatus = 'Pass';        description = 'The foreign agent identity holds no delegated permission from this project''s curated dangerous-permission list.' }
        @{ code = 'AGT-003-NO-CANDIDATES';          resultStatus = 'NotApplicable'; description = 'No AgentIdentity entity was confirmed foreign in the evidence set.' }
        @{ code = 'AGT-003-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'AgentIdentity, AgentIdentityBlueprintPrincipal, or ServicePrincipalApiPermissions evidence was not fully collected for this snapshot.' }
        @{ code = 'AGT-003-EVALUATOR-ERROR';        resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AgentIdentity entity confirmed foreign. Fail if it holds at least one Microsoft-Graph-scoped delegated permission from the curated dangerous-permission list, Pass otherwise. NotApplicable (single tenant-scoped result) only if zero foreign agent identities exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureForeignAgentIdentityExtensiveApiDelegatedPrivilegeControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review why a foreign-owned agent identity was granted a dangerous delegated permission. Revoke the consent grant; if ongoing access is required, scope it to the narrowest permission that satisfies the actual integration need.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-oauth2permissiongrants?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/permissions-reference'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic or its full multi-tier risk-scoring system. See ENT-004.psd1''s own provenance notes for the shared curation methodology and the architecture-fork resolution this control family is part of.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-003' }
    )

    baselineDependency = $null
}
