@{
    <#
        Fixed-state control (VNext build order item 8; per-role PIM direct/permanent assignment
        policy setting -- distinct from PIM-003's activation-duration setting, see this control's
        own requiredEvidenceDomains/rationale). Control ID/title continuity from
        15-feature-parity-matrix.md section 3.3's EntraFalcon-derived canonical finding registry
        (PIM-005, "Tier-0 Roles Allow Permanent Active Assignments", severity 1) -- per
        docs/VNext.md's review-not-reuse policy, only that listing's title/severity/category was
        used; EntraFalcon's own check logic was not read. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.
    #>
    controlId   = 'PIM-005'
    version     = '1.0.0'
    title       = 'Tier-0 Role Allows Permanent Active Assignments'
    description = "For each curated Tier-0 directory role, checks whether an admin can create a direct, permanent (non-expiring) active assignment to the role -- distinct from PIM-003's check, which covers how long a self-activated eligible assignment stays active, not a directly-assigned one."
    rationale   = 'Microsoft''s own PIM role-settings documentation directly names this exact configuration: "Allow permanent active assignment: Resource administrators can assign permanent active assignments." A permanent active assignment bypasses PIM''s core value proposition entirely for that specific grant -- there is no activation event, no time bound, and no automatic expiry to force periodic re-justification, regardless of how the role''s eligible-activation settings (PIM-003/004/007/009) are configured.'
    severity    = 1
    category    = 'Privileged Roles'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'RoleManagementPolicyAssignment')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'RoleManagementPolicy.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per curated Tier-0 role (same set PIM-002/003/004 use) that has a corresponding RoleManagementPolicyAssignment in evidence. A single tenant-scoped NotApplicable result is returned if none of the curated roles were present as DirectoryRole entities at all.'

    reasonCodes = @(
        @{ code = 'PIM-005-PERMANENT-ASSIGNMENT-ALLOWED'; resultStatus = 'Fail';         description = 'The role''s Admin/Assignment-level expiration rule has isExpirationRequired=false -- a permanent active assignment is allowed.' }
        @{ code = 'PIM-005-EXPIRATION-REQUIRED';           resultStatus = 'Pass';        description = 'The role''s Admin/Assignment-level expiration rule has isExpirationRequired=true.' }
        @{ code = 'PIM-005-NO-TIER-ZERO-ROLES-ACTIVATED';  resultStatus = 'NotApplicable'; description = 'None of the curated Tier-0 roles were present as DirectoryRole entities in the evidence set.' }
        @{ code = 'PIM-005-EVIDENCE-NOT-COLLECTED';        resultStatus = 'NotEvaluated'; description = 'DirectoryRole or RoleManagementPolicyAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'PIM-005-EVALUATOR-ERROR';               resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per curated Tier-0 role with a corresponding RoleManagementPolicyAssignment. Fail when adminAssignmentIsExpirationRequired is false (or absent, since Microsoft''s own JSON representation reflects "permanent allowed" as the field''s permissive default state when unset). Pass when true. A role with no corresponding RoleManagementPolicyAssignment entity is skipped (no result). NotApplicable (single tenant-scoped result) only if no curated Tier-0 role exists in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureTierZeroPermanentAssignmentControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Enable "Expire active assignment after" (Assignment duration settings, active assignment) in the role''s PIM role settings and set a bounded maximum duration, instead of allowing permanent active assignments.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'
        'https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyexpirationrule?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Control ID/title reused from 15-feature-parity-matrix.md section 3.3's EntraFalcon-derived canonical finding registry (PIM-005) for tracking continuity; check logic authored independently from Microsoft's own PIM role-settings documentation (re-fetched 2026-08-07), not read from or ported out of EntraFalcon's source, per docs/VNext.md's review-not-reuse policy. Confirming this control needed the Admin/Assignment-level expiration rule specifically (not the same EndUser/Assignment field PIM-003 reads) required checking Microsoft's own admin-UI documentation directly -- see src/Normalization/NormalizeRoleManagementPolicyAssignment.ps1's own DESCRIPTION for the full writeup of this distinction and why it mattered."
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PIM-005' }
    )

    baselineDependency = $null
}
