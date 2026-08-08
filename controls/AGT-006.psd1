@{
    <#
        VNext build order item 2, new-evidence phase (the "Extensive API Privileges" architecture-
        fork item, resolved 2026-08-08). Thin wrapper over Get-EntraPostureExtensiveApiPrivilege
        ControlResult (ExtensiveApiPrivilege.ps1) -- see that function's own header comment for
        the shared logic every sibling control (ENT-004/005/009/010, AGT-002/003/006/007,
        MAI-001) reuses. Keys deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'AGT-006'
    version     = '1.0.0'
    title       = 'Internal Agent Identities with Extensive API Privileges (as Application)'
    description = 'For each AgentIdentity entity NOT confirmed foreign, checks whether it holds a Microsoft-Graph-scoped application permission from this project''s curated dangerous-permission list.'
    rationale   = 'A dangerous application permission grants a standing, credential-based path to escalate privilege or take over the directory outright, independent of any explicit role assignment -- a tenant-owned agent identity holding one is still a real risk if its own credentials or blueprint are ever compromised.'
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

    applicability = 'Evaluated once per AgentIdentity entity not confirmed foreign. NotApplicable (a single tenant-scoped result) if every AgentIdentity was confirmed foreign, or none exist at all.'

    reasonCodes = @(
        @{ code = 'AGT-006-EXTENSIVE-PRIVILEGE';    resultStatus = 'Fail';         description = 'The internal agent identity holds a Microsoft-Graph-scoped application permission from this project''s curated dangerous-permission list.' }
        @{ code = 'AGT-006-NO-EXTENSIVE-PRIVILEGE'; resultStatus = 'Pass';        description = 'The internal agent identity holds no application permission from this project''s curated dangerous-permission list.' }
        @{ code = 'AGT-006-NO-CANDIDATES';          resultStatus = 'NotApplicable'; description = 'No AgentIdentity entity not confirmed foreign was present in the evidence set.' }
        @{ code = 'AGT-006-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'AgentIdentity, AgentIdentityBlueprintPrincipal, or ServicePrincipalApiPermissions evidence was not fully collected for this snapshot.' }
        @{ code = 'AGT-006-EVALUATOR-ERROR';        resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AgentIdentity entity not confirmed foreign. Fail if it holds at least one Microsoft-Graph-scoped application permission from the curated dangerous-permission list, Pass otherwise. NotApplicable (single tenant-scoped result) only if that population is empty. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureInternalAgentIdentityExtensiveApiApplicationPrivilegeControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review why the agent identity was granted a dangerous application permission. Remove the grant; if ongoing access is required, scope it to the narrowest permission that satisfies the actual integration need.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/permissions-reference'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic or its full multi-tier risk-scoring system. See ENT-004.psd1''s own provenance notes for the shared curation methodology and the architecture-fork resolution this control family is part of.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-006' }
    )

    baselineDependency = $null
}
