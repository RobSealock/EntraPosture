@{
    <#
        Relational control (VNext build order item 7; matches the matrix's own class label --
        "must compare the referencing CA policy's state and exclusion scope against the actual
        population of users/roles the context is meant to protect... not evaluable from the
        policy or the PIM setting alone"). Keys are deliberately camelCase -- see XTA-001.psd1's
        header comment for why.

        Gated on AUTHCTX-001: only evaluated for context/role pairings AUTHCTX-001 already
        confirmed have at least one referencing Conditional Access policy (a pairing with zero
        referencing policies produces an AUTHCTX-001 Fail and no AUTHCTX-002 result at all -- the
        same gating relationship AR-002 has to AR-001, per the matrix design).
    #>
    controlId   = 'AUTHCTX-002'
    version     = '1.0.0'
    title       = 'Authentication Context''s Referencing Policy Is Disabled, Report-Only, or Excludes the Assigned Population'
    description = 'For a context/role pairing already confirmed to have at least one referencing Conditional Access policy (AUTHCTX-001 passed), every referencing policy is disabled, is report-only, or its exclusion scope removes some or all of the role''s actual eligible/active assignees -- so no referencing policy actually enforces the requirement for the population it is meant to protect.'
    rationale   = "Microsoft's own PIM role-settings documentation states the backup MFA-fallback mechanism explicitly does not trigger when the Conditional Access policy targeting the configured authentication context is turned off, is in report-only mode, or has an eligible user excluded from the policy -- unlike AUTHCTX-001's complete-absence case, which degrades gracefully to plain MFA, these three cases get no fallback whatsoever. A context in this state looks configured and safe in the admin UI while providing none of the protection an admin believes is in place, which is a worse operational state than AUTHCTX-001's honestly-visible absence."
    severity    = 3
    category    = 'Authentication Context'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AuthenticationContextClassReference', 'RoleManagementPolicyAssignment', 'ConditionalAccessPolicy', 'DirectoryRoleAssignment', 'PimEligible', 'TransitiveMemberOf')
    requiredPermissions     = @(
        @{ scope = 'AuthenticationContext.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagementPolicy.Read.Directory'; confirmed = $true }
        @{ scope = 'Policy.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagement.Read.Directory'; confirmed = $true }
        @{ scope = 'GroupMember.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per (context, role) pairing where the context is published and PIM-configured on that role AND at least one Conditional Access policy references the context (i.e. AUTHCTX-001 passed for that context). A single tenant-scoped NotApplicable result is returned if no such pairing exists.'

    reasonCodes = @(
        @{ code = 'AUTHCTX-002-POLICY-DISABLED';    resultStatus = 'Fail';         description = 'Every referencing policy is state=disabled.' }
        @{ code = 'AUTHCTX-002-POLICY-REPORT-ONLY'; resultStatus = 'Fail';         description = 'No referencing policy is state=disabled, but none is enabled either -- at least one is report-only (enabledForReportingButNotEnforced).' }
        @{ code = 'AUTHCTX-002-ASSIGNEE-EXCLUDED';  resultStatus = 'Fail';         description = 'At least one referencing policy is enabled, but every enabled referencing policy''s exclusion scope removes one or more of the role''s actual eligible/active assignees -- takes priority over the two reason codes above when it applies, since an enabled-but-excluding policy is the most specific, most actionable failure state.' }
        @{ code = 'AUTHCTX-002-EFFECTIVE';          resultStatus = 'Pass';        description = 'At least one referencing policy is enabled and its exclusion scope does not remove any of the role''s actual eligible/active assignees.' }
        @{ code = 'AUTHCTX-002-NO-APPLICABLE-PAIRINGS'; resultStatus = 'NotApplicable'; description = 'No (context, role) pairing exists where AUTHCTX-001 would pass -- either no context is published and PIM-configured, or none has any referencing policy at all.' }
        @{ code = 'AUTHCTX-002-EVIDENCE-NOT-COLLECTED'; resultStatus = 'NotEvaluated'; description = 'Required evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AUTHCTX-002-EVALUATOR-ERROR';    resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per (context, role) pairing AUTHCTX-001 would pass for. Pass when at least one referencing policy is enabled and excludes none of the role''s actual eligible/active assignees. Fail otherwise, with the specific reason (all disabled; none enabled but at least one report-only; or at least one enabled but every enabled one excludes an assignee -- checked in that priority order, see AUTHCTX-002-ASSIGNEE-EXCLUDED''s own description). NotApplicable (single tenant-scoped result) only when zero applicable pairings exist. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureAuthenticationContextEffectivenessControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Enable any disabled referencing policy. Move report-only referencing policies to enforced once validated. Remove exclusions that cover actual PIM-eligible or active assignees of the role, or record them as an approved, owned, time-bounded deviation instead of leaving the gap unexplained.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-configure-role-settings'
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "No source-tool prior art -- same lineage as AUTHCTX-001 (see that control's own provenance notes). Deliberate v1 boundary, not silently assumed complete: exclusion-scope coverage checking implements conditions.users.excludeUsers (direct match) and conditions.users.excludeGroups (direct match, or transitive membership via already-collected TransitiveMemberOf evidence) -- conditions.users.excludeRoles (excluding by ''any user who also holds role X'') is not implemented, since it is a materially rarer exclusion pattern and this project's own engineering discipline prefers a narrower, fully-correct check over a broader, partially-verified one. A pairing whose only exclusion path is an excludeRoles entry will be reported Pass/EFFECTIVE even if that entry would, in a real tenant, exclude some assignees -- tracked as a known boundary, not a silent gap, matching how AUTHCTX-001's own design doc names the SharePoint/Purview/custom-app assignment surfaces as an equivalent, explicitly-scoped-out boundary."
    }

    externalMappings = @()

    baselineDependency = $null
}
