@{
    <#
        VNext build order item 13. See AGT-001.psd1's header comment for this control family's
        shared build-order/provenance context. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'AGT-011'
    version     = '1.0.0'
    title       = 'Foreign Agent Users with Entra ID Roles'
    description = 'For each AgentUser entity whose parent AgentIdentity is confirmed foreign, checks whether it holds an Active DirectoryRoleAssignment to a curated Tier-0 role.'
    rationale   = 'An agent user is a distinct, user-derived principal from its parent agent identity -- Microsoft''s own documentation states agent users operate under "no privileged admin role assignments" by platform design, but this project verifies rather than assumes that claim (see AGT-013/014''s own applicability note on the unresolved reachability question). A foreign agent user found holding a Tier-0 role combines the same cross-tenant exposure AGT-004 checks for agent identities with a state Microsoft''s own platform claims should not be reachable at all.'
    severity    = 3
    category    = 'Agent Identities'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AgentUser', 'AgentIdentity', 'AgentIdentityBlueprintPrincipal', 'DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'User.ReadBasic.All'; confirmed = $true }
        @{ scope = 'AgentIdentity.Read.All'; confirmed = $true }
        @{ scope = 'AgentIdentityBlueprintPrincipal.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per AgentUser entity whose parent AgentIdentity is confirmed foreign (derived transitively through identityParentId). An AgentUser whose parent''s foreign-ness cannot be resolved is excluded, producing no result for it. NotApplicable (a single tenant-scoped result) if no AgentUser was confirmed foreign at all.'

    reasonCodes = @(
        @{ code = 'AGT-011-FOREIGN-TIER-ZERO-ROLE';        resultStatus = 'Fail';         description = 'The foreign agent user holds an Active assignment to a curated Tier-0 role.' }
        @{ code = 'AGT-011-NO-TIER-ZERO-ROLE';             resultStatus = 'Pass';        description = 'The foreign agent user holds no Active assignment to any curated Tier-0 role.' }
        @{ code = 'AGT-011-NO-FOREIGN-AGENT-USERS';        resultStatus = 'NotApplicable'; description = 'No AgentUser entity was confirmed foreign (via its parent agent identity) in the evidence set.' }
        @{ code = 'AGT-011-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'AgentUser, AgentIdentity, AgentIdentityBlueprintPrincipal, DirectoryRole, or DirectoryRoleAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AGT-011-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AgentUser entity whose parent identity is confirmed foreign. Fail if an Active DirectoryRoleAssignment to a curated Tier-0 role exists for that agent user, Pass otherwise. An AgentUser whose parent''s foreign-ness is unresolvable produces zero results for it. NotApplicable (single tenant-scoped result) only if zero foreign agent users exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureForeignAgentUserEntraRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Investigate immediately -- Microsoft''s own documentation states agent users should never hold privileged admin role assignments. Remove the assignment and report the finding, since its existence may indicate a platform-enforcement gap rather than an ordinary misconfiguration.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/agentuser-list?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/agentuser?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 11''s design spec for tracking continuity, not a port of EntraFalcon''s own source logic. "Foreign" is derived transitively through identityParentId -> parent AgentIdentity -> that identity''s own blueprint principal''s appOwnerOrganizationId (Get-EntraPostureAgentUserForeignMap), not a direct field on AgentUser itself -- confirmed live against the agentUser resource page''s own property table, re-fetched 2026-08-07: identityParentId "references the object ID of the associated agent identity."'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-011' }
    )

    baselineDependency = $null
}
