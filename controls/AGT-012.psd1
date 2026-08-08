@{
    <#
        VNext build order item 13. See AGT-001.psd1's header comment for this control family's
        shared build-order/provenance context. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'AGT-012'
    version     = '1.0.0'
    title       = 'Foreign Agent Users with Azure Roles'
    description = 'For each AgentUser entity whose parent AgentIdentity is confirmed foreign, checks whether it holds any Azure RBAC role assignment.'
    rationale   = 'Same concern as AGT-011, applied to the Azure RBAC authorization plane.'
    severity    = 3
    category    = 'Agent Identities'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AgentUser', 'AgentIdentity', 'AgentIdentityBlueprintPrincipal', 'AzureRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'User.ReadBasic.All'; confirmed = $true }
        @{ scope = 'AgentIdentity.Read.All'; confirmed = $true }
        @{ scope = 'AgentIdentityBlueprintPrincipal.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per AgentUser entity whose parent AgentIdentity is confirmed foreign. An AgentUser whose parent''s foreign-ness cannot be resolved is excluded, producing no result for it. NotApplicable (a single tenant-scoped result) if no AgentUser was confirmed foreign at all.'

    reasonCodes = @(
        @{ code = 'AGT-012-FOREIGN-AZURE-ROLE';            resultStatus = 'Fail';         description = 'The foreign agent user holds at least one Azure RBAC role assignment.' }
        @{ code = 'AGT-012-NO-AZURE-ROLE';                 resultStatus = 'Pass';        description = 'The foreign agent user holds no Azure RBAC role assignment.' }
        @{ code = 'AGT-012-NO-FOREIGN-AGENT-USERS';        resultStatus = 'NotApplicable'; description = 'No AgentUser entity was confirmed foreign (via its parent agent identity) in the evidence set.' }
        @{ code = 'AGT-012-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'AgentUser, AgentIdentity, AgentIdentityBlueprintPrincipal, or AzureRoleAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AGT-012-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AgentUser entity whose parent identity is confirmed foreign. Fail if any AzureRoleAssignment entity''s properties.principalId matches that agent user, Pass otherwise. An AgentUser whose parent''s foreign-ness is unresolvable produces zero results for it. NotApplicable (single tenant-scoped result) only if zero foreign agent users exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureForeignAgentUserAzureRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review the Azure RBAC role assignment; remove it unless a specific, reviewed business need requires it.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/agentuser-list?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 11''s design spec for tracking continuity, not a port of EntraFalcon''s own source logic. Same transitive-foreign derivation as AGT-011.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-012' }
    )

    baselineDependency = $null
}
