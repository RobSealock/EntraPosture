@{
    <#
        VNext build order item 13. See AGT-001.psd1's header comment for this control family's
        shared build-order/provenance context. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'AGT-017'
    version     = '1.0.0'
    title       = 'Agent Identity Blueprints with Non-Tier-0 Owner'
    description = 'For each AgentIdentityBlueprint entity, checks whether every owner holds an Active DirectoryRoleAssignment to a curated Tier-0 role -- inverse framing from every other AGT-* finding: Fails when the owner set includes anyone who does NOT hold a curated Tier-0 role.'
    rationale   = 'A blueprint is the template every agent identity created from it inherits its configuration and preauthorized permissions from -- an owner who can modify or extend that template but does not themselves hold accountable, already-privileged status is a governance gap: the blueprint''s own trust boundary is only as strong as its least-privileged owner.'
    severity    = 2
    category    = 'Agent Identities'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AgentIdentityBlueprint', 'DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'AgentIdentityBlueprint.Read.All'; confirmed = $true }
        @{ scope = 'Application.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per collected AgentIdentityBlueprint entity, regardless of owner count. NotApplicable (a single tenant-scoped result) only if the tenant has no agent identity blueprints at all; a specific blueprint with zero owners produces its own per-blueprint NotApplicable result rather than being folded into that tenant-scoped case.'

    reasonCodes = @(
        @{ code = 'AGT-017-NON-TIER-ZERO-OWNER';   resultStatus = 'Fail';         description = 'At least one of the blueprint''s owners has no Active assignment to any curated Tier-0 role.' }
        @{ code = 'AGT-017-TIER-ZERO-OWNER-ONLY';  resultStatus = 'Pass';        description = 'Every one of the blueprint''s owners has an Active assignment to a curated Tier-0 role.' }
        @{ code = 'AGT-017-NO-OWNERS';             resultStatus = 'NotApplicable'; description = 'The blueprint has no collected owner.' }
        @{ code = 'AGT-017-NO-BLUEPRINTS';         resultStatus = 'NotApplicable'; description = 'No AgentIdentityBlueprint entity was present in the evidence set.' }
        @{ code = 'AGT-017-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'AgentIdentityBlueprint, DirectoryRole, or DirectoryRoleAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AGT-017-EVALUATOR-ERROR';       resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per collected AgentIdentityBlueprint entity. A blueprint with zero owners produces its own NotApplicable result (AGT-017-NO-OWNERS). Otherwise: Fail if any owner lacks an Active Tier-0 DirectoryRoleAssignment, Pass if every owner has one. The overall tenant-scoped NotApplicable (AGT-017-NO-BLUEPRINTS) applies only when zero blueprints exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureAgentBlueprintOwnerTierControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Add a Tier-0-role-holding owner, or transfer ownership entirely to already-privileged, accountable principals. Remove owners who do not hold Tier-0 privilege from a blueprint capable of minting new agent identities.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/application-list-owners?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/agentid-platform-overview?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 11''s design spec for tracking continuity, not a port of EntraFalcon''s own source logic. Owners are collected via the ordinary application-owners endpoint (an agent identity blueprint inherits application) -- confirmed live against the "List owners of an application" Graph reference page, re-fetched 2026-08-07; no agent-specific owners permission exists.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-017' }
    )

    baselineDependency = $null
}
