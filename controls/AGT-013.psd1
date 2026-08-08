@{
    <#
        VNext build order item 13, resolved from "blocked" to built 2026-08-08 -- see
        00-open-questions.md's writeup for why. Keys deliberately camelCase.
    #>
    controlId   = 'AGT-013'
    version     = '1.0.0'
    title       = 'Internal Agent Users with Privileged Entra ID Roles'
    description = 'For each AgentUser entity whose parent AgentIdentity is confirmed internal (non-foreign), checks whether it holds an Active DirectoryRoleAssignment to a curated Tier-0 role.'
    rationale   = 'Microsoft''s own agentUser documentation states agent users operate under "no privileged admin role assignments" -- this control verifies that claim directly against live evidence rather than assuming it holds, the same "verify, don''t assume the platform enforces its own claim" discipline AGT-011''s foreign counterpart already applies.'
    severity    = 2
    category    = 'Agent Identities'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AgentUser', 'AgentIdentity', 'AgentIdentityBlueprintPrincipal', 'DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'User.ReadBasic.All'; confirmed = $true }
        @{ scope = 'AgentIdentity.Read.All'; confirmed = $true }
        @{ scope = 'AgentIdentityBlueprintPrincipal.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per AgentUser entity whose parent AgentIdentity is confirmed internal. An AgentUser whose parent''s foreign-ness cannot be resolved is excluded, producing no result for it. NotApplicable (a single tenant-scoped result) if no AgentUser was confirmed internal at all.'

    reasonCodes = @(
        @{ code = 'AGT-013-INTERNAL-TIER-ZERO-ROLE';        resultStatus = 'Fail';         description = 'The internal agent user holds an Active assignment to a curated Tier-0 role.' }
        @{ code = 'AGT-013-NO-TIER-ZERO-ROLE';              resultStatus = 'Pass';        description = 'The internal agent user holds no Active assignment to any curated Tier-0 role.' }
        @{ code = 'AGT-013-NO-INTERNAL-AGENT-USERS';        resultStatus = 'NotApplicable'; description = 'No AgentUser entity was confirmed internal (non-foreign) in the evidence set.' }
        @{ code = 'AGT-013-EVIDENCE-NOT-COLLECTED';         resultStatus = 'NotEvaluated'; description = 'AgentUser, AgentIdentity, AgentIdentityBlueprintPrincipal, DirectoryRole, or DirectoryRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'AGT-013-EVALUATOR-ERROR';                resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AgentUser entity confirmed internal. Fail if an Active DirectoryRoleAssignment to a curated Tier-0 role exists for that agent user, Pass otherwise. An AgentUser whose parent''s foreign-ness is unresolvable produces zero results for it. NotApplicable (single tenant-scoped result) only if zero internal agent users exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureInternalAgentUserEntraRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Investigate immediately and remove the assignment -- an agent user holding a Tier-0 role is a state Microsoft''s own platform documentation claims should not be reachable at all, so its presence may indicate a platform-enforcement gap rather than an ordinary misconfiguration.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/agentuser?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Originally left "blocked" pending live-tenant confirmation of platform-reachability (15-feature-parity-matrix.md section 11). Built 2026-08-08 as a defensive check regardless of that open question, the same precedent EM-002''s EM002-ASSIGNMENT-PAST-EXPIRATION already established for this project (see that control''s own provenance notes) -- if Microsoft''s platform claim holds, this control simply never Fails in practice; if it does not, the gap is exactly what this project exists to surface.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-013' }
    )

    baselineDependency = $null
}
