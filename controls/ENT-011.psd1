@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08, batch
        4). Keys deliberately camelCase.
    #>
    controlId   = 'ENT-011'
    version     = '1.0.0'
    title       = 'Internal Enterprise Applications with Privileged Entra ID Roles'
    description = 'For each ServicePrincipal entity confirmed internal (non-foreign), checks whether it holds an Active DirectoryRoleAssignment to a curated Tier-0 role.'
    rationale   = 'Same standing-privilege concern PIM-002 applies to human role holders, applied to an application principal: an internally-authored application still warrants scrutiny when it holds Tier-0 privilege, since an application has no interactive owner or MFA/Conditional Access surface of its own to gate its use of that privilege.'
    severity    = 2
    category    = 'Applications'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ServicePrincipal', 'DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'Application.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per ServicePrincipal entity confirmed internal (non-foreign). NotApplicable (a single tenant-scoped result) if no ServicePrincipal entity exists at all.'

    reasonCodes = @(
        @{ code = 'ENT-011-INTERNAL-TIER-ZERO-ROLE';        resultStatus = 'Fail';         description = 'The internal service principal holds an Active assignment to a curated Tier-0 role.' }
        @{ code = 'ENT-011-NO-TIER-ZERO-ROLE';              resultStatus = 'Pass';        description = 'The internal service principal holds no Active assignment to any curated Tier-0 role.' }
        @{ code = 'ENT-011-NO-INTERNAL-SERVICE-PRINCIPALS'; resultStatus = 'NotApplicable'; description = 'No ServicePrincipal entity was present in the evidence set.' }
        @{ code = 'ENT-011-EVIDENCE-NOT-COLLECTED';         resultStatus = 'NotEvaluated'; description = 'ServicePrincipal, DirectoryRole, or DirectoryRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'ENT-011-EVALUATOR-ERROR';                resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per ServicePrincipal entity confirmed internal. Fail if an Active DirectoryRoleAssignment to a curated Tier-0 role exists for it, Pass otherwise. NotApplicable (single tenant-scoped result) only if zero service principals exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureInternalServicePrincipalEntraRoleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Convert the standing assignment to a PIM-eligible one, or remove it if the application does not require continuous Tier-0 privilege.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. Same correlation as ENT-006, internal population, lower severity matching the matrix''s own foreign-vs-internal severity split precedent.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'ENT-011' }
    )

    baselineDependency = $null
}
