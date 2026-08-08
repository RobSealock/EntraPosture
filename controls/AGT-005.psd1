@{
    <#
        VNext build order item 13. See AGT-001.psd1's header comment for this control family's
        shared build-order/provenance context. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'AGT-005'
    version     = '1.0.0'
    title       = 'Foreign Agent Identities with Azure Roles'
    description = 'For each AgentIdentity entity confirmed foreign (its blueprint''s appOwnerOrganizationId differs from this tenant), checks whether it holds any Azure RBAC role assignment.'
    rationale   = 'Same cross-tenant blast-radius concern as AGT-004, applied to the Azure RBAC authorization plane instead of Entra ID directory roles -- a foreign agent identity with any Azure role assignment can act against Azure resources without this tenant''s own admin consent review ever having considered that specific automated principal.'
    severity    = 3
    category    = 'Agent Identities'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AgentIdentity', 'AgentIdentityBlueprintPrincipal', 'AzureRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'AgentIdentity.Read.All'; confirmed = $true }
        @{ scope = 'AgentIdentityBlueprintPrincipal.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per AgentIdentity entity confirmed foreign. An AgentIdentity whose foreign-ness cannot be resolved is excluded, producing no result for it. NotApplicable (a single tenant-scoped result) if no AgentIdentity was confirmed foreign at all.'

    reasonCodes = @(
        @{ code = 'AGT-005-FOREIGN-AZURE-ROLE';            resultStatus = 'Fail';         description = 'The foreign agent identity holds at least one Azure RBAC role assignment.' }
        @{ code = 'AGT-005-NO-AZURE-ROLE';                 resultStatus = 'Pass';        description = 'The foreign agent identity holds no Azure RBAC role assignment.' }
        @{ code = 'AGT-005-NO-FOREIGN-AGENT-IDENTITIES';   resultStatus = 'NotApplicable'; description = 'No AgentIdentity entity was confirmed foreign in the evidence set.' }
        @{ code = 'AGT-005-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'AgentIdentity, AgentIdentityBlueprintPrincipal, or AzureRoleAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AGT-005-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AgentIdentity entity confirmed foreign. Fail if any AzureRoleAssignment entity''s properties.principalId matches that identity, Pass otherwise. An AgentIdentity whose foreign-ness is unresolvable produces zero results for it. NotApplicable (single tenant-scoped result) only if zero foreign agent identities exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureForeignAgentIdentityAzureRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review why a foreign-owned agent identity blueprint was granted an Azure RBAC role. Remove the assignment unless a specific, reviewed business need requires it.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/agentidentity-list?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/agentidentityblueprintprincipal-list?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 11''s design spec for tracking continuity, not a port of EntraFalcon''s own source logic. Reuses AGT-004''s foreign-derivation correlation (Get-EntraPostureAgentIdentityForeignMap) against the existing AzureRoleAssignment entity domain -- no new evidence collection needed for the Azure-role half.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-005' }
    )

    baselineDependency = $null
}
