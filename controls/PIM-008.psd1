@{
    <#
        Fixed-state control (VNext build order item 8; per-role PIM notification setting).
        Control ID/title continuity from 15-feature-parity-matrix.md section 3.3's
        EntraFalcon-derived canonical finding registry (PIM-008, "Tier-0 Roles Without
        Notification", severity 1) -- per docs/VNext.md's review-not-reuse policy, only that
        listing's title/severity/category was used; EntraFalcon's own check logic was not read.
        Keys are deliberately camelCase -- see XTA-001.psd1's header comment for why.

        Weaker citation basis than PIM-003 through PIM-007, stated honestly rather than implied
        otherwise: Microsoft's own PIM role-settings documentation describes the Notifications
        tab's controls (which recipients, which email types) without stating that notifications
        must be enabled at all -- this is this project's own judgment call, not a Microsoft
        directive, the same class of reasoned-but-not-quoted threshold PIM-003's 4-hour bound and
        PRIV-001's upper bound already are.
    #>
    controlId   = 'PIM-008'
    version     = '1.0.0'
    title       = 'Tier-0 Role Activation Notifications Are Fully Disabled'
    description = "For each curated Tier-0 directory role, checks whether every notification for the role's self-activation event (admin, requestor, and approver recipients alike) has been disabled -- no default recipients and no explicitly-added recipients on any of them."
    rationale   = "This project's own judgment call, not a Microsoft-quoted requirement: Microsoft's PIM notification emails are the only near-real-time signal this project is aware of that a Tier-0 role was just activated, short of actively monitoring sign-in/audit logs. A tenant that has gone out of its way to silence every recipient path for that event has removed a legitimate, low-cost detection signal for no documented benefit. Scoped only to the self-activation event's own notifications (the same EndUser/Assignment target every other control in this family reasons about) -- this control does not evaluate eligibility-assignment or admin-configuration notifications, which are a different, lower-relevance event for this project's threat model."
    severity    = 1
    category    = 'Privileged Roles'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('DirectoryRole', 'RoleManagementPolicyAssignment')
    requiredPermissions     = @(
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'RoleManagementPolicy.Read.Directory'; confirmed = $true }
    )

    applicability = 'Evaluated once per curated Tier-0 role (same set PIM-002 through PIM-007 use) that has a corresponding RoleManagementPolicyAssignment in evidence. A single tenant-scoped NotApplicable result is returned if none of the curated roles were present as DirectoryRole entities at all.'

    reasonCodes = @(
        @{ code = 'PIM-008-NOTIFICATIONS-DISABLED'; resultStatus = 'Fail';         description = 'Every activation-notification rule for this role has no default recipients enabled and no explicit recipients configured.' }
        @{ code = 'PIM-008-NOTIFICATIONS-ENABLED';  resultStatus = 'Pass';        description = 'At least one activation-notification rule for this role has a default or explicit recipient configured.' }
        @{ code = 'PIM-008-NO-TIER-ZERO-ROLES-ACTIVATED'; resultStatus = 'NotApplicable'; description = 'None of the curated Tier-0 roles were present as DirectoryRole entities in the evidence set.' }
        @{ code = 'PIM-008-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'DirectoryRole or RoleManagementPolicyAssignment evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'PIM-008-EVALUATOR-ERROR';        resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per curated Tier-0 role with a corresponding RoleManagementPolicyAssignment. Fail when activationNotificationEnabled is false. Pass when true. A role with no corresponding RoleManagementPolicyAssignment entity is skipped (no result). NotApplicable (single tenant-scoped result) only if no curated Tier-0 role exists in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureTierZeroActivationNotificationControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Restore at least one notification recipient path (default recipients, or an explicit recipient) for the role''s activation notifications in PIM role settings.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings'
        'https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicynotificationrule?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Control ID/title reused from 15-feature-parity-matrix.md section 3.3's EntraFalcon-derived canonical finding registry (PIM-008) for tracking continuity; check logic authored independently, not read from or ported out of EntraFalcon's source, per docs/VNext.md's review-not-reuse policy. Unlike PIM-003 through PIM-007, this control's threshold (notifications should not be fully silenced) is this project's own reasoned judgment call, not traced to a specific Microsoft directive -- stated as such in this control's own rationale rather than presented with the same citation strength as the others in this family."
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'PIM-008' }
    )

    baselineDependency = $null
}
