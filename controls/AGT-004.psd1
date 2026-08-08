@{
    <#
        VNext build order item 13. See AGT-001.psd1's header comment for this control family's
        shared build-order/provenance context. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'AGT-004'
    version     = '1.0.0'
    title       = 'Foreign Agent Identities with Entra ID Roles'
    description = 'For each AgentIdentity entity whose underlying blueprint is owned by a different tenant (appOwnerOrganizationId differs from this tenant), checks whether it holds an Active DirectoryRoleAssignment to a curated Tier-0 role (Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator).'
    rationale   = 'An agent identity created from a blueprint your tenant does not own is, functionally, a third party''s automated principal operating inside your directory -- the same cross-tenant blast-radius concern XTA-001/002 already apply to human/application cross-tenant access, applied here to an autonomous agent that can act without a human in the loop. A foreign agent identity holding a Tier-0 role combines that external-trust exposure with the highest privilege tier this project curates.'
    severity    = 3
    category    = 'Agent Identities'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AgentIdentity', 'AgentIdentityBlueprintPrincipal', 'DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'AgentIdentity.Read.All'; confirmed = $true }
        @{ scope = 'AgentIdentityBlueprintPrincipal.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per AgentIdentity entity confirmed foreign (its blueprint''s appOwnerOrganizationId differs from this tenant). An AgentIdentity whose foreign-ness cannot be resolved (blueprint principal evidence missing) is excluded, producing no result for it. NotApplicable (a single tenant-scoped result) if no AgentIdentity was confirmed foreign at all.'

    reasonCodes = @(
        @{ code = 'AGT-004-FOREIGN-TIER-ZERO-ROLE';        resultStatus = 'Fail';         description = 'The foreign agent identity holds an Active assignment to a curated Tier-0 role.' }
        @{ code = 'AGT-004-NO-TIER-ZERO-ROLE';             resultStatus = 'Pass';        description = 'The foreign agent identity holds no Active assignment to any curated Tier-0 role.' }
        @{ code = 'AGT-004-NO-FOREIGN-AGENT-IDENTITIES';   resultStatus = 'NotApplicable'; description = 'No AgentIdentity entity was confirmed foreign in the evidence set.' }
        @{ code = 'AGT-004-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'AgentIdentity, AgentIdentityBlueprintPrincipal, DirectoryRole, or DirectoryRoleAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AGT-004-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AgentIdentity entity confirmed foreign. Fail if an Active DirectoryRoleAssignment to a curated Tier-0 role exists for that identity, Pass otherwise. An AgentIdentity whose foreign-ness is unresolvable produces zero results for it (excluded from this control''s population entirely, the same "nothing to check" shape PIM-002 already established for a role with zero assignments). NotApplicable (single tenant-scoped result) only if zero foreign agent identities exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureForeignAgentIdentityEntraRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review why a foreign-owned agent identity blueprint was granted a Tier-0 role. Remove the standing assignment; if ongoing access is required, scope it to a narrower, non-Tier-0 role and govern activation through PIM.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/agentidentity-list?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/agentidentityblueprintprincipal-list?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 11''s design spec for tracking continuity, not a port of EntraFalcon''s own source logic. The agentIdentityBlueprintId-to-appOwnerOrganizationId correlation (via AgentIdentityBlueprintPrincipal.properties.appId, NOT its entityId -- confirmed directly on the live agentIdentity resource page''s own property table, re-fetched 2026-08-07) is independently authored and verified against Microsoft''s live documentation, not assumed from the original design spec''s prose alone.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-004' }
    )

    baselineDependency = $null
}
