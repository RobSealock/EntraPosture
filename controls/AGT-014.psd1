@{
    <#
        VNext build order item 13, resolved from "blocked" to built 2026-08-08. Keys deliberately
        camelCase. See AGT-013.psd1's header comment for shared context.
    #>
    controlId   = 'AGT-014'
    version     = '1.0.0'
    title       = 'Internal Agent Users with Privileged Azure Roles'
    description = 'For each AgentUser entity whose parent AgentIdentity is confirmed internal (non-foreign), checks whether it holds any Azure RBAC role assignment.'
    rationale   = 'Azure roles are a separate authorization plane from Entra ID directory roles, so this may be reachable even if AGT-013 is not -- worth checking independently, not assumed to share an answer, per AGT-012''s own note on the same point for the foreign population.'
    severity    = 2
    category    = 'Agent Identities'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AgentUser', 'AgentIdentity', 'AgentIdentityBlueprintPrincipal', 'AzureRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'User.ReadBasic.All'; confirmed = $true }
        @{ scope = 'AgentIdentity.Read.All'; confirmed = $true }
        @{ scope = 'AgentIdentityBlueprintPrincipal.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per AgentUser entity whose parent AgentIdentity is confirmed internal. An AgentUser whose parent''s foreign-ness cannot be resolved is excluded, producing no result for it. NotApplicable (a single tenant-scoped result) if no AgentUser was confirmed internal at all.'

    reasonCodes = @(
        @{ code = 'AGT-014-INTERNAL-AZURE-ROLE';     resultStatus = 'Fail';         description = 'The internal agent user holds at least one Azure RBAC role assignment.' }
        @{ code = 'AGT-014-NO-AZURE-ROLE';           resultStatus = 'Pass';        description = 'The internal agent user holds no Azure RBAC role assignment.' }
        @{ code = 'AGT-014-NO-INTERNAL-AGENT-USERS'; resultStatus = 'NotApplicable'; description = 'No AgentUser entity was confirmed internal (non-foreign) in the evidence set.' }
        @{ code = 'AGT-014-EVIDENCE-NOT-COLLECTED';  resultStatus = 'NotEvaluated'; description = 'AgentUser, AgentIdentity, AgentIdentityBlueprintPrincipal, or AzureRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'AGT-014-EVALUATOR-ERROR';         resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AgentUser entity confirmed internal. Fail if any AzureRoleAssignment entity''s properties.principalId matches that agent user, Pass otherwise. An AgentUser whose parent''s foreign-ness is unresolvable produces zero results for it. NotApplicable (single tenant-scoped result) only if zero internal agent users exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureInternalAgentUserAzureRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review the Azure RBAC role assignment; remove it unless a specific, reviewed business need requires it for an agent user specifically.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/agentuser?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Originally left "blocked" pending live-tenant confirmation of platform-reachability. Built 2026-08-08 as a defensive check, the same EM-002 precedent AGT-013''s own provenance notes cite.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-014' }
    )

    baselineDependency = $null
}
