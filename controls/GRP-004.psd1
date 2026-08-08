@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Keys
        deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'GRP-004'
    version     = '1.0.0'
    title       = 'Dynamic Groups with Potentially Dangerous Membership Rules'
    description = 'For each dynamically-membered Group entity, checks whether its membershipRule references a user attribute a member (or, for two specific attributes, an inviter) could set to manipulate their own dynamic-group membership.'
    rationale   = 'A dynamic group''s membership is meant to be admin-controlled via its rule -- but if the rule keys off an attribute an ordinary user can edit about themselves (preferred language, mobile phone, business phones) or that is influenceable through the guest-invitation flow (UPN, mail), any user can add themselves to the group and inherit whatever access it grants.'
    severity    = 2
    category    = 'Groups'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('Group', 'AuthorizationPolicy')
    requiredPermissions     = @(
        @{ scope = 'Group.Read.All'; confirmed = $true }
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per Group entity with groupTypes containing DynamicMembership and a non-empty membershipRule. NotApplicable (a single tenant-scoped result) if no such group exists.'

    reasonCodes = @(
        @{ code = 'GRP-004-DANGEROUS-MEMBERSHIP-RULE'; resultStatus = 'Fail';         description = 'The dynamic group''s membership rule references at least one self-editable (or, given the tenant''s guest-invite policy, invite-influenceable) user attribute.' }
        @{ code = 'GRP-004-SAFE-MEMBERSHIP-RULE';      resultStatus = 'Pass';        description = 'The dynamic group''s membership rule references no known self-editable or invite-influenceable attribute.' }
        @{ code = 'GRP-004-NO-DYNAMIC-GROUPS';         resultStatus = 'NotApplicable'; description = 'No dynamically-membered Group entity with a membership rule was present in the evidence set.' }
        @{ code = 'GRP-004-EVIDENCE-NOT-COLLECTED';    resultStatus = 'NotEvaluated'; description = 'Group or AuthorizationPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'GRP-004-EVALUATOR-ERROR';           resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per dynamically-membered Group entity with a non-empty membership rule. Fail if the rule references user.preferredLanguage, user.mobilePhone, or user.businessPhones (always checked), or user.userPrincipalName/user.mail (checked only when AuthorizationPolicy.allowInvitesFrom is not "none"); Pass otherwise. NotApplicable (single tenant-scoped result) only if no applicable dynamic group exists at all. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureDangerousDynamicGroupRuleControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Rewrite the dynamic membership rule to key off attributes only an administrator can set (department, employeeId, extension attributes), not attributes the user themselves (or an inviter, for guest-linked attributes) can edit.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity. The two-tier curated attribute list (always-risky vs. invite-dependent) independently re-derived from EntraFalcon''s own publicly visible check_Tenant.psm1, then confirmed against Microsoft''s own user-attribute self-service-editability documentation before inclusion, re-fetched 2026-08-08. membershipRule and groupTypes confirmed present in the default GET /v1.0/groups response (no $select needed); allowInvitesFrom already collected for COL-002.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'GRP-004' }
    )

    baselineDependency = $null
}
