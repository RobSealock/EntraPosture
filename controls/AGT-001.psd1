@{
    <#
        VNext build order item 13 (agent identity / PIM-for-Groups): the first of 9 designable
        AGT-* controls built from 15-feature-parity-matrix.md section 11's design spec
        (2026-08-07). Control ID/title reused from that section's own canonical numbering
        (consolidated from EntraFalcon's EF-AGT-*/EF-AGTBP-*/EF-AGTBL-* findings) for tracking
        continuity, not a port of EntraFalcon's own source logic, which was not read for this
        pass -- the same disposition GRP-005/PIM-002 already established. Keys are deliberately
        camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'AGT-001'
    version     = '1.0.0'
    title       = 'Agent Identity Blueprints With Client Secrets'
    description = 'For each AgentIdentityBlueprint entity, checks whether it has at least one password credential (client secret) configured.'
    rationale   = 'A blueprint with a client secret configured is authenticatable outside the platform''s own certificate/managed-identity-based agent authentication model -- a password credential on the template every agent identity created from it inherits is a durable, exportable secret that widens the blueprint''s own attack surface beyond what agent identity authentication is designed to require.'
    severity    = 2
    category    = 'Agent Identities'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AgentIdentityBlueprint')
    requiredPermissions     = @(
        @{ scope = 'AgentIdentityBlueprint.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per collected AgentIdentityBlueprint entity -- always applicable to every blueprint. NotApplicable (a single tenant-scoped result) only if the tenant has no agent identity blueprints at all.'

    reasonCodes = @(
        @{ code = 'AGT-001-HAS-PASSWORD-CREDENTIAL';    resultStatus = 'Fail';         description = 'The blueprint has at least one password credential configured.' }
        @{ code = 'AGT-001-NO-PASSWORD-CREDENTIAL';     resultStatus = 'Pass';        description = 'The blueprint has no password credential configured.' }
        @{ code = 'AGT-001-NO-BLUEPRINTS';              resultStatus = 'NotApplicable'; description = 'No AgentIdentityBlueprint entity was present in the evidence set.' }
        @{ code = 'AGT-001-EVIDENCE-NOT-COLLECTED';     resultStatus = 'NotEvaluated'; description = 'AgentIdentityBlueprint evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AGT-001-EVALUATOR-ERROR';            resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per collected AgentIdentityBlueprint entity. Fail when passwordCredentialCount is greater than zero. Pass when it is zero. NotApplicable (single tenant-scoped result) only if zero blueprints exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureAgentBlueprintClientSecretControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Remove the password credential from the agent identity blueprint and rely on the platform''s own certificate-based or managed authentication path instead.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/agentidentityblueprint-list?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/agentid-platform-overview?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 11''s design spec (itself consolidated from EntraFalcon''s Agent Identity Blueprint findings for tracking continuity). Independently authored against this project''s own AgentIdentityBlueprint evidence contract -- EntraFalcon''s actual source logic was not read for this pass. Endpoint, permission scope, and passwordCredentials field presence confirmed live against the "List agentIdentityBlueprint objects" Microsoft Graph reference page, re-fetched 2026-08-07.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-001' }
    )

    baselineDependency = $null
}
