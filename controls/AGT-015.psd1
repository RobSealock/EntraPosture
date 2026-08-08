@{
    <#
        VNext build order item 13. See AGT-001.psd1's header comment for this control family's
        shared build-order/provenance context. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'AGT-015'
    version     = '1.0.0'
    title       = 'Agent Users Owning CAP-Related Groups'
    description = 'For each AgentUser entity that owns at least one Group, checks whether any owned group is itself referenced in a Conditional Access policy''s includeGroups/excludeGroups condition.'
    rationale   = 'An agent user that owns a group referenced in a Conditional Access policy can add or remove members of that group -- including itself, or other principals -- and thereby change who a live Conditional Access policy applies to or exempts, without ever needing a Conditional Access administration permission of its own. This is an indirect, easy-to-overlook path to influencing access-control enforcement.'
    severity    = 2
    category    = 'Agent Identities'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AgentUser', 'Group', 'ConditionalAccessPolicy')
    requiredPermissions     = @(
        @{ scope = 'User.ReadBasic.All'; confirmed = $true }
        @{ scope = 'Directory.Read.All'; confirmed = $true }
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per AgentUser entity that owns at least one Group (via ownedObjects). An AgentUser that owns zero groups produces no result. NotApplicable (a single tenant-scoped result) if no AgentUser owns any Group at all. Evidence collection for this control is delegated-only -- ownedObjects has no application-permission path at all per Microsoft''s own reference documentation -- so this control is structurally NotEvaluated for any run using CertificateAppOnly authentication, regardless of granted permissions.'

    reasonCodes = @(
        @{ code = 'AGT-015-OWNS-CAP-GROUP';                resultStatus = 'Fail';         description = 'The agent user owns at least one Group referenced in a Conditional Access policy''s user condition.' }
        @{ code = 'AGT-015-NO-CAP-GROUP-OWNERSHIP';        resultStatus = 'Pass';        description = 'The agent user owns at least one Group, but none are referenced in any Conditional Access policy''s user condition.' }
        @{ code = 'AGT-015-NO-AGENT-USER-GROUP-OWNERSHIP'; resultStatus = 'NotApplicable'; description = 'No AgentUser entity owns any Group in the evidence set.' }
        @{ code = 'AGT-015-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'AgentUser, Group, or ConditionalAccessPolicy evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected) -- including, structurally, any CertificateAppOnly run, since ownedObjects has no application-permission path.' }
        @{ code = 'AGT-015-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AgentUser entity that owns at least one Group. Fail if any owned group''s entityId appears in any ConditionalAccessPolicy''s conditions.users.includeGroups or excludeGroups, Pass otherwise. An AgentUser that owns zero groups produces zero results for it. NotApplicable (single tenant-scoped result) only if zero agent users own any group at all in evidence. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureAgentUserCapGroupOwnershipControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Remove the agent user from the group''s owner list, or transfer ownership to an accountable human owner, if the agent user does not have a specific, reviewed need to manage that group''s membership.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/user-list-ownedobjects?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/agentuser-list?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 11''s design spec for tracking continuity, not a port of EntraFalcon''s own source logic. The ownedObjects endpoint''s "Application permission: Not supported" constraint was confirmed directly against the live "List ownedObjects" Graph reference page, re-fetched 2026-08-07 -- a real Microsoft platform constraint documented in this control''s own applicability field, not an oversight.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'AGT-015' }
    )

    baselineDependency = $null
}
