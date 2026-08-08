@{
    <#
        VNext build order item 13. See AGT-001.psd1's header comment for this control family's
        shared build-order/provenance context. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'AGT-009'
    version     = '1.0.0'
    title       = 'Internal Agent Identities with Privileged Azure Roles'
    description = 'For each AgentIdentity entity confirmed internal (non-foreign), checks whether it holds any Azure RBAC role assignment.'
    rationale   = 'Same standing-privilege concern as AGT-008, applied to the Azure RBAC authorization plane.'
    severity    = 2
    category    = 'Agent Identities'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AgentIdentity', 'AgentIdentityBlueprintPrincipal', 'AzureRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'AgentIdentity.Read.All'; confirmed = $true }
        @{ scope = 'AgentIdentityBlueprintPrincipal.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per AgentIdentity entity confirmed internal (non-foreign). An AgentIdentity whose foreign-ness cannot be resolved is excluded, producing no result for it. NotApplicable (a single tenant-scoped result) if no AgentIdentity was confirmed internal at all.'

    reasonCodes = @(
        @{ code = 'AGT-009-INTERNAL-AZURE-ROLE';           resultStatus = 'Fail';         description = 'The internal agent identity holds at least one Azure RBAC role assignment.' }
        @{ code = 'AGT-009-NO-AZURE-ROLE';                 resultStatus = 'Pass';        description = 'The internal agent identity holds no Azure RBAC role assignment.' }
        @{ code = 'AGT-009-NO-INTERNAL-AGENT-IDENTITIES';  resultStatus = 'NotApplicable'; description = 'No AgentIdentity entity was confirmed internal (non-foreign) in the evidence set.' }
        @{ code = 'AGT-009-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'AgentIdentity, AgentIdentityBlueprintPrincipal, or AzureRoleAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AGT-009-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AgentIdentity entity confirmed internal. Fail if any AzureRoleAssignment entity''s properties.principalId matches that identity, Pass otherwise. An AgentIdentity whose foreign-ness is unresolvable produces zero results for it. NotApplicable (single tenant-scoped result) only if zero internal agent identities exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureInternalAgentIdentityAzureRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review the Azure RBAC role assignment; remove it or narrow its scope if the agent identity does not require it.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/agentidentity-list?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 11''s design spec for tracking continuity, not a port of EntraFalcon''s own source logic. Same correlation as AGT-005, internal population.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-009' }
    )

    baselineDependency = $null
}
