@{
    <#
        Relational control (VNext build order item 7; matches the matrix's own class label,
        15-feature-parity-matrix.md section 10 -- "requires correlating every published context
        against every CA policy's conditions.applications.includeAuthenticationContextClassReferences
        to determine whether a given context is referenced anywhere at all"). Keys are
        deliberately camelCase -- see XTA-001.psd1's header comment for why.

        Exists to close a specific correctness gap in PIM-009 (not yet built as of this control --
        see this file's provenance notes): PIM-009 only checks that a Tier-0 role's activation is
        *configured* to require an authentication context; it can't detect a configured-but-
        non-functional context (unpublished, or published but never actually wired to a
        Conditional Access policy), which would let PIM-009 report a false Pass.
    #>
    controlId   = 'AUTHCTX-001'
    version     = '1.0.0'
    title       = 'Authentication Context Assigned With No Conditional Access Policy Referencing It'
    description = "A published (isAvailable=true) authentication context is configured as a PIM role-activation requirement on at least one directory role, but no Conditional Access policy in the tenant (in any state) references that context's ID in its target-resources condition."
    rationale   = "Microsoft's own Conditional Access documentation states a context can't be deleted while a CA policy still references it or while it's published -- a safety net that only fires on deletion, not on assignment. Nothing prevents assigning a published, PIM-configured context that was never backed by a policy in the first place. For PIM specifically this degrades to plain multifactor authentication rather than zero protection (Microsoft's own PIM role-settings documentation states an unconfigured-context backup mechanism kicks in when no Conditional Access policy in the tenant targets the configured context at all) -- so this control's severity is calibrated to 'intent not met' (an admin expecting phishing-resistant MFA + compliant device is silently getting generic MFA instead) rather than 'no protection at all', which is AUTHCTX-002's sharper failure mode."
    severity    = 2
    category    = 'Authentication Context'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AuthenticationContextClassReference', 'RoleManagementPolicyAssignment', 'ConditionalAccessPolicy')
    requiredPermissions     = @(
        @{ scope = 'AuthenticationContext.Read.All'; confirmed = $true }
        @{ scope = 'RoleManagementPolicy.Read.Directory'; confirmed = $true }
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per published (isAvailable=true) authentication context that is also configured as an activation requirement (authenticationContextEnabled=true) on at least one directory role''s PIM policy. A single tenant-scoped NotApplicable result is returned if no context meets both conditions -- not one result per unpublished or PIM-unconfigured context, which are excluded from evaluation entirely rather than reported.'

    reasonCodes = @(
        @{ code = 'AUTHCTX-001-NO-REFERENCING-POLICY';    resultStatus = 'Fail';         description = 'Zero Conditional Access policies, in any state, reference this context ID in conditions.applications.includeAuthenticationContextClassReferences.' }
        @{ code = 'AUTHCTX-001-REFERENCED';                resultStatus = 'Pass';        description = 'At least one Conditional Access policy (any state) references this context ID.' }
        @{ code = 'AUTHCTX-001-NO-APPLICABLE-CONTEXTS';    resultStatus = 'NotApplicable'; description = 'No published, PIM-configured authentication context exists in evidence at all.' }
        @{ code = 'AUTHCTX-001-EVIDENCE-NOT-COLLECTED';    resultStatus = 'NotEvaluated'; description = 'AuthenticationContextClassReference, RoleManagementPolicyAssignment, or ConditionalAccessPolicy evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'AUTHCTX-001-EVALUATOR-ERROR';           resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per published, PIM-role-activation-configured authentication context. Fail when zero Conditional Access policies (in any state -- enabled, disabled, or report-only) reference the context ID at all; this control does not yet judge whether a referencing policy is actually effective, that is AUTHCTX-002''s job. Pass when at least one policy references it, regardless of that policy''s own state. NotApplicable (single tenant-scoped result) only when no context is both published and PIM-configured. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself (engineering plan section 9.2).'

    evaluatorFunctionName  = 'Test-EntraPostureAuthenticationContextCoverageControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Create and enable a Conditional Access policy targeting this authentication context before -- or immediately after discovering -- it is configured as a PIM activation requirement, per Microsoft''s own stated recommended order. If the context is not actually in use, unpublish it (isAvailable=false) or remove it from the role''s PIM activation settings instead of leaving a non-functional requirement configured.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/authenticationcontextclassreference?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps'
        'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-configure-role-settings'
        'https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyauthenticationcontextrule?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "No source-tool prior art -- 15-feature-parity-matrix.md section 10 confirms this pair has no digest MS-ENTRA-* backing and rests entirely on direct Microsoft documentation, not on EntraFalcon/caOptics/CA Insight/Conditional Access Validator (none of which was read for this pass, per docs/VNext.md's review-not-reuse discipline). Exists specifically as a documented correctness dependency for PIM-009 ('Tier-0 Roles Without Authentication Context or Approval'), which is itself not yet built as of this control (VNext build order item 8) -- this control does not require PIM-009 to exist first, since it checks a different, orthogonal property (is the referenced context functional) using the same underlying RoleManagementPolicyAssignment evidence PIM-009 will also read. The correlation between a role's authenticationContextClaimValue and an authenticationContextClassReference's own id is treated as an inference, not a directly-quoted Microsoft fact -- see NormalizeRoleManagementPolicyAssignment.ps1's own DESCRIPTION for the precise citation-strength caveat."
    }

    externalMappings = @()

    baselineDependency = @{
        documentationUrl  = 'https://learn.microsoft.com/en-us/graph/api/resources/authenticationcontextclassreference?view=graph-rest-1.0'
        asOfDate          = '2026-08-07'
        citationStrength  = 'DirectQuote'
    }
}
