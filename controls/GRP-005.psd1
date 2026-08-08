@{
    <#
        Transitive control (Phase 7, third tier: "fixed-state, relational, transitive, then
        temporal/PIM"): evaluates Group entities flagged isAssignableToRole=true against their
        TransitiveMemberOf relationship count -- the transitive-closure relationship type Phase 6
        built specifically to distinguish "who is actually, ultimately a member" from direct
        membership alone (relationship.schema.json's isTransitive field). Keys are deliberately
        camelCase -- see XTA-001.psd1's header comment for why.

        Control ID and title reuse 15-feature-parity-matrix.md section 3.3's canonical
        EntraFalcon-derived finding registry entry GRP-005 "Weak Protection of Sensitive Groups"
        (severity 3) -- but this implementation is a narrower, independently-designed check, not
        a port of EntraFalcon's logic: the matrix's own text says GRP-005 "draws on several
        EF-GRP-* signals" from EntraFalcon's source, which was not read for this pass. This
        control checks exactly one dimension -- role-assignable groups should have small,
        bounded, reviewable membership, the same "recovery risk vs. blast-radius risk" reasoning
        PRIV-001 applies directly to the Global Administrator role, applied here to any group
        that can itself carry a role assignment (making its membership functionally equivalent
        to direct role assignment). It does not check owner counts, guest membership, or dynamic
        membership rules, which EntraFalcon's fuller "Weak Protection of Sensitive Groups"
        finding may also cover -- documented as a known, deliberate v1 boundary in
        00-open-questions.md's Phase 7 section, using the same control ID because the underlying
        concern (role-assignable groups need scrutiny) is the same, not because the check is a
        complete port.
    #>
    controlId   = 'GRP-005'
    version     = '1.0.0'
    title       = 'Role-Assignable Group Has Excessive Transitive Membership'
    description = 'For each Group entity flagged isAssignableToRole=true, counts its TransitiveMemberOf relationships and checks the count against a small, bounded threshold.'
    rationale   = 'A group flagged isAssignableToRole=true can itself be assigned an Entra role, making every current and future transitive member of that group a role holder by extension -- membership in the group is functionally equivalent to a direct role assignment. The same over-provisioning/blast-radius reasoning PRIV-001 applies to the Global Administrator role''s own direct membership applies here: an unbounded, growing membership list defeats the purpose of using a role-assignable group as a curated, reviewable privilege boundary.'
    severity    = 3
    category    = 'Groups'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('Group', 'TransitiveMemberOf')
    requiredPermissions     = @(
        @{ scope = 'Group.Read.All'; confirmed = $true }
        @{ scope = 'GroupMember.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per Group entity with isAssignableToRole=true. NotApplicable (a single tenant-scoped result) if the tenant has no role-assignable groups at all.'

    reasonCodes = @(
        @{ code = 'GRP-005-EXCESSIVE-TRANSITIVE-MEMBERSHIP'; resultStatus = 'Fail';         description = 'The role-assignable group''s TransitiveMemberOf count exceeds 5.' }
        @{ code = 'GRP-005-MEMBERSHIP-WITHIN-BOUND';          resultStatus = 'Pass';        description = 'The role-assignable group''s TransitiveMemberOf count is 5 or fewer (including zero).' }
        @{ code = 'GRP-005-NO-ROLE-ASSIGNABLE-GROUPS';        resultStatus = 'NotApplicable'; description = 'No Group entity with isAssignableToRole=true was present in the evidence set.' }
        @{ code = 'GRP-005-EVIDENCE-NOT-COLLECTED';           resultStatus = 'NotEvaluated'; description = 'Group or TransitiveMemberOf evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'GRP-005-EVALUATOR-ERROR';                  resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per role-assignable group. Fail when its TransitiveMemberOf count exceeds 5 (a heuristic threshold, not a Microsoft-documented value -- see baselineDependency). Pass when 5 or fewer, including zero (an unused role-assignable group is not itself a finding). NotApplicable (single tenant-scoped result) only if zero role-assignable groups exist in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureSensitiveGroupProtectionControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Review the group''s membership and remove accounts that do not require the role this group carries. Convert broad, standing group membership to PIM-eligible role assignment where individual accountability and time-bounded activation are preferred over standing group-based access.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept'
        'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3''s EntraFalcon-derived canonical finding registry (GRP-005, "Weak Protection of Sensitive Groups") for tracking continuity, but the check itself is independently authored against this project''s own TransitiveMemberOf evidence and PRIV-001''s established range-check pattern -- not a port of EntraFalcon''s actual EF-GRP-* source logic, which was not read for this pass. See this file''s own header comment for the full scope narrowing.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'GRP-005' }
    )

    baselineDependency = $null
}
