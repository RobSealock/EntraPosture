@{
    <#
        VNext build order item 13. See AGT-001.psd1's header comment for this control family's
        shared build-order/provenance context. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'AGT-008'
    version     = '1.0.0'
    title       = 'Internal Agent Identities with Privileged Entra ID Roles'
    description = 'For each AgentIdentity entity confirmed internal (non-foreign -- its blueprint is owned by this tenant), checks whether it holds an Active DirectoryRoleAssignment to a curated Tier-0 role.'
    rationale   = 'Same standing-privilege concern PIM-002 applies to human/service-principal role holders, applied to an autonomous agent identity: an internally-authored agent still warrants scrutiny when it holds Tier-0 privilege, since an autonomous, non-interactive principal acting continuously at Tier-0 is a materially different risk profile than a human admin who is present and accountable for each action.'
    severity    = 2
    category    = 'Agent Identities'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AgentIdentity', 'AgentIdentityBlueprintPrincipal', 'DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'AgentIdentity.Read.All'; confirmed = $true }
        @{ scope = 'AgentIdentityBlueprintPrincipal.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per AgentIdentity entity confirmed internal (non-foreign). An AgentIdentity whose foreign-ness cannot be resolved is excluded, producing no result for it. NotApplicable (a single tenant-scoped result) if no AgentIdentity was confirmed internal at all.'

    reasonCodes = @(
        @{ code = 'AGT-008-INTERNAL-TIER-ZERO-ROLE';       resultStatus = 'Fail';         description = 'The internal agent identity holds an Active assignment to a curated Tier-0 role.' }
        @{ code = 'AGT-008-NO-TIER-ZERO-ROLE';             resultStatus = 'Pass';        description = 'The internal agent identity holds no Active assignment to any curated Tier-0 role.' }
        @{ code = 'AGT-008-NO-INTERNAL-AGENT-IDENTITIES';  resultStatus = 'NotApplicable'; description = 'No AgentIdentity entity was confirmed internal (non-foreign) in the evidence set.' }
        @{ code = 'AGT-008-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'AgentIdentity, AgentIdentityBlueprintPrincipal, DirectoryRole, or DirectoryRoleAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AGT-008-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AgentIdentity entity confirmed internal. Fail if an Active DirectoryRoleAssignment to a curated Tier-0 role exists for that identity, Pass otherwise. An AgentIdentity whose foreign-ness is unresolvable produces zero results for it. NotApplicable (single tenant-scoped result) only if zero internal agent identities exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureInternalAgentIdentityEntraRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Convert the standing assignment to a PIM-eligible one, or remove it if the agent identity does not require continuous Tier-0 privilege.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/agentidentity-list?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 11''s design spec for tracking continuity, not a port of EntraFalcon''s own source logic. Same correlation as AGT-004, internal population, lower severity matching the matrix''s own foreign-vs-internal severity split precedent.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-008' }
    )

    baselineDependency = $null
}
