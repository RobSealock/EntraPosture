@{
    <#
        VNext build order item 2, the 109-row backlog continuation (batch 15, 2026-08-08). The
        last of the 10 ranked-value findings before the genuine beta-API blocker
        (ENT-002/AGT-010/AGT-016). New RoleAssignmentScope evidence -- see
        CollectRoleAssignmentScopes.ps1's own header comment for why the existing
        DirectoryRoleAssignment evidence can't answer this. Keys deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'CAP-011'
    version     = '1.0.0'
    title       = 'Conditional Access Policy Includes Roles With Scoped Assignments'
    description = 'For each enabled Conditional Access policy that targets specific directory roles, checks whether any of those roles has an administrative-unit-scoped assignment -- a holder Conditional Access role targeting does not cover.'
    rationale   = 'Conditional Access policies that target users by directory role only match tenant-wide role assignments; an administrative-unit-scoped holder of that same role is silently excluded from the policy''s protection, a gap an administrator relying on role-based targeting to protect "every Global Administrator" (for example) would not expect.'
    severity    = 2
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ConditionalAccessPolicy', 'RoleAssignmentScope')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'One result per enabled Conditional Access policy whose own users.includeRoles condition names at least one role. A single tenant-scoped NotApplicable result if no such policy exists.'

    reasonCodes = @(
        @{ code = 'CAP-011-SCOPED-ASSIGNMENT-GAP';       resultStatus = 'Fail';         description = 'At least one role named in the policy''s own includeRoles condition has an administrative-unit-scoped assignment.' }
        @{ code = 'CAP-011-NO-SCOPED-ASSIGNMENT-GAP';    resultStatus = 'Pass';        description = 'No role named in the policy''s own includeRoles condition has an administrative-unit-scoped assignment.' }
        @{ code = 'CAP-011-NO-ROLE-SCOPED-POLICIES';     resultStatus = 'NotApplicable'; description = 'No enabled Conditional Access policy names any role in its own users.includeRoles condition.' }
        @{ code = 'CAP-011-EVIDENCE-NOT-COLLECTED';      resultStatus = 'NotEvaluated'; description = 'ConditionalAccessPolicy or RoleAssignmentScope evidence was not fully collected for this snapshot.' }
        @{ code = 'CAP-011-EVALUATOR-ERROR';             resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per enabled Conditional Access policy whose conditions.users.includeRoles is non-empty. Fail if any included role (matched by roleTemplateId against RoleAssignmentScope.targetEntityId) has at least one Active assignment with scope=administrativeUnit; Pass if every included role''s assignments are all directory-wide (or the role currently has no assignments at all). A single tenant-scoped NotApplicable result if no enabled policy names any role. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureCaPolicyScopedRoleAssignmentControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Either broaden the affected role assignment to tenant-wide scope so Conditional Access role targeting covers it, or replace the policy''s role-based targeting with an explicit user/group assignment (e.g. a role-assignable group containing every Tier-0 holder, scoped or not) that Conditional Access does support.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups'
        'https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity. Genuinely new evidence source (RoleAssignmentScope, via GET /roleManagement/directory/roleAssignments) -- the existing DirectoryRoleAssignment collector''s own endpoint (/directoryRoles/{id}/members) structurally cannot return administrative-unit-scoped assignments, the specific gap this project''s own 00-open-questions.md deferred this control for in section 3.3''s original triage pass. Population/threshold shape (per-policy, not per-role) chosen independently of any source tool -- not a claim of behavioral equivalence to EntraFalcon''s own check.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'CAP-011' }
    )

    baselineDependency = $null
}
