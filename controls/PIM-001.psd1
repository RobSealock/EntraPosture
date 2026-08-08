@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Keys
        deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'PIM-001'
    version     = '1.0.0'
    title       = 'PIM for Entra Roles Not Used'
    description = 'Checks whether Privileged Identity Management is actively used for Entra ID role assignments at all -- Fail if zero PIM-eligible Entra ID role assignments exist anywhere in the tenant, Pass if at least one does.'
    rationale   = 'A tenant with no PIM-eligible role assignments at all is running every privileged role as a standing, always-active assignment (or has none configured through PIM at all) -- basic PIM adoption is the prerequisite every other PIM-* control in this project''s registry (PIM-002 through PIM-009) already assumes.'
    severity    = 3
    category    = 'PIM'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'PimEligibility')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'PrivilegedEligibilitySchedule.Read.AzureADGroup'; confirmed = $false }
    )

    applicability = 'A single tenant-scoped result. Always evaluated once PimEligibility evidence has been collected.'

    reasonCodes = @(
        @{ code = 'PIM-001-NOT-ADOPTED'; resultStatus = 'Fail';         description = 'No PIM-eligible Entra ID role assignment exists in the tenant.' }
        @{ code = 'PIM-001-ADOPTED';     resultStatus = 'Pass';        description = 'At least one PIM-eligible Entra ID role assignment exists in the tenant.' }
        @{ code = 'PIM-001-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'PimEligibility evidence was not fully collected for this snapshot -- including a tenant not licensed for PIM, which this feature requires Entra ID P2 for.' }
        @{ code = 'PIM-001-EVALUATOR-ERROR'; resultStatus = 'Error';    description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Exactly one tenant-scoped result. Fail if the PimEligible relationship set is empty, Pass otherwise. Deliberately does not attempt to independently detect Entra ID P2 licensing status -- if PIM itself is unlicensed, the underlying collector call fails and this control surfaces as NotEvaluated via the orchestration layer''s own partial-evidence handling, not a value this evaluator computes itself. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPosturePimEntraRoleAdoptionControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Enable Privileged Identity Management (requires Entra ID P2) and convert standing role assignments to PIM-eligible, time-bound activations for privileged Entra ID roles.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityscheduleinstances?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic (that source additionally pre-checks PIM licensing directly, which this project deliberately does not replicate -- see expectedResultSemantics). Reuses the existing PimEligible relationship evidence PIM-002 already established, zero new evidence needed.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PIM-001' }
    )

    baselineDependency = $null
}
