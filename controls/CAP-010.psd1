@{
    <#
        VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08). See
        CAP-001.psd1's header comment for shared context. Keys deliberately camelCase.

        Narrowed from the source finding's own "Tier-0/Tier-1" framing to Tier-0 only -- this
        project has never independently curated a "Tier-1" role set (unlike the Tier-0 set every
        PIM-00x/CA-002/AGT-* control already reuses), and inventing one for this control alone
        would be an uncited, unreviewed judgment call. A real scope narrowing, stated as such.
    #>
    controlId   = 'CAP-010'
    version     = '1.0.0'
    title       = 'Conditional Access Policy Missing Used Tier-0 Roles'
    description = 'For each curated Tier-0 role with at least one Active DirectoryRoleAssignment, checks whether any enabled Conditional Access policy''s conditions.users.includeRoles names that role.'
    rationale   = 'A Tier-0 role that is actively in use but never targeted by any Conditional Access role condition has no Conditional-Access-enforced control over its holders at all -- the coarser precursor question CA-001''s own per-scenario coverage check assumes is already answered for Global Administrator specifically.'
    severity    = 3
    category    = 'Conditional Access'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('ConditionalAccessPolicy', 'DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per curated Tier-0 role with at least one Active DirectoryRoleAssignment. NotApplicable (a single tenant-scoped result) if none of the curated Tier-0 roles have any Active assignment.'

    reasonCodes = @(
        @{ code = 'CAP-010-ROLE-COVERED';                   resultStatus = 'Pass';         description = 'The Tier-0 role is named in at least one enabled policy''s role condition.' }
        @{ code = 'CAP-010-ROLE-NOT-COVERED';                resultStatus = 'Fail';         description = 'The Tier-0 role has an Active assignment but is not named in any enabled policy''s role condition.' }
        @{ code = 'CAP-010-NO-TIER-ZERO-ROLES-ACTIVATED';    resultStatus = 'NotApplicable'; description = 'None of the curated Tier-0 roles have any Active assignment in the evidence set.' }
        @{ code = 'CAP-010-EVIDENCE-NOT-COLLECTED';          resultStatus = 'NotEvaluated'; description = 'ConditionalAccessPolicy, DirectoryRole, or DirectoryRoleAssignment evidence was not fully collected for this snapshot.' }
        @{ code = 'CAP-010-EVALUATOR-ERROR';                 resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per curated Tier-0 role with an Active assignment. Pass if any enabled policy''s includeRoles names it; Fail otherwise. NotApplicable (single tenant-scoped result) only if zero curated Tier-0 roles are active in evidence. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureTierZeroRoleCaCoverageControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Add the uncovered Tier-0 role to an enabled Conditional Access policy''s role condition with an appropriate grant control (e.g. MFA or a phishing-resistant authentication strength).'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. Scoped to the curated Tier-0 role set only -- see this file''s own header comment on the "Tier-1" narrowing.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'CAP-010' }
    )

    baselineDependency = $null
}
