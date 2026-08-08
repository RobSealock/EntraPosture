@{
    <#
        Relationship control (Phase 5's "one relationship control" vertical-slice exit
        criterion): evaluates DirectoryRoleAssignment relationships targeting the Global
        Administrator directory role. Keys are deliberately camelCase -- see XTA-001.psd1's
        header comment for why.
    #>
    controlId   = 'PRIV-001'
    version     = '1.0.0'
    title       = 'Global Administrator active membership count is within Microsoft''s recommended range'
    description = 'Counts Active DirectoryRoleAssignment relationships targeting the Global Administrator directory role and checks the count is neither too low (bus-factor/recovery risk) nor too high (over-provisioning risk).'
    rationale   = 'Too few Global Administrators risks losing tenant recovery capability if an account is lost or unavailable; too many expands the blast radius of any single compromised admin account. Microsoft''s own guidance directly recommends a minimum of two: "organizations have two cloud-only emergency access accounts permanently assigned the Global Administrator role" (security-planning, re-verified live 2026-08-07). The upper bound of 4 is this project''s own judgment call, not a specific number Microsoft states -- the same page''s broader theme (minimize standing privileged access, prefer PIM/JIT activation over permanent assignment) supports keeping the population small and bounded, but does not name a specific ceiling.'
    severity    = 4
    category    = 'Privileged Roles'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'DirectoryRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
    )

    applicability = 'Always applicable when directory role and role-assignment evidence was collected -- every tenant has a Global Administrator role, and Graph only omits it from /directoryRoles if it has literally never been activated (handled as NotApplicable, not assumed impossible).'

    reasonCodes = @(
        @{ code = 'PRIV-001-TOO-FEW-GLOBAL-ADMINS';           resultStatus = 'Fail';         description = 'Fewer than 2 Active Global Administrator assignments -- recovery/bus-factor risk.' }
        @{ code = 'PRIV-001-TOO-MANY-GLOBAL-ADMINS';          resultStatus = 'Fail';         description = 'More than 4 Active Global Administrator assignments -- over-provisioning risk.' }
        @{ code = 'PRIV-001-GLOBAL-ADMIN-COUNT-WITHIN-RANGE'; resultStatus = 'Pass';         description = 'Between 2 and 4 (inclusive) Active Global Administrator assignments.' }
        @{ code = 'PRIV-001-NO-GA-ROLE-ACTIVATED';            resultStatus = 'NotApplicable'; description = 'No Global Administrator DirectoryRole entity was present in the evidence set.' }
        @{ code = 'PRIV-001-EVIDENCE-NOT-COLLECTED';          resultStatus = 'NotEvaluated'; description = 'DirectoryRole or DirectoryRoleAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'PRIV-001-EVALUATOR-ERROR';                 resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Fail (too few) when the Active-assignment count targeting the Global Administrator role is below 2. Fail (too many) when it exceeds 4. Pass when it is 2, 3, or 4. NotApplicable only if no Global Administrator role entity exists in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself (engineering plan section 9.2).'

    evaluatorFunctionName  = 'Test-EntraPosturePrivilegedRoleAssignmentControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'If the count is below 2, activate at least one additional Global Administrator (ideally via PIM eligibility rather than a standing assignment) to avoid a single point of failure for tenant recovery. If the count is above 4, review each assignment and remove standing Global Administrator access for accounts that do not require it continuously, converting genuinely-privileged users to PIM-eligible assignments activated only when needed.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning'
        'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Clean-room control authored directly from Microsoft Learn Entra role-management guidance. Similar "Global Administrator count" checks exist in spirit across several community tools (EntraFalcon among them), but this control''s logic was not read from or ported out of any specific source tool''s code -- independently authored against the DirectoryRoleAssignment evidence contract this project already defined in Phase 3. Phase 10 re-verification (2026-08-07, ADR-035): the security-planning reference was re-fetched live and directly supports the lower bound of 2 (a quoted minimum-two-break-glass-accounts recommendation); it does not state a specific upper bound, which remains this project''s own judgment call, now stated as such in this control''s own rationale rather than implied to be Microsoft-specified. The second reference (best-practices) was not re-fetched this pass.'
    }

    externalMappings = @()

    baselineDependency = $null
}
