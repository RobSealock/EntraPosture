@{
    <#
        Relational control (v.next build order item 11), admitted into v1 scope by the deviation
        record in 00-open-questions.md item 28 -- see 15-feature-parity-matrix.md section 8 for
        the full design this control implements. Keys are deliberately camelCase -- see
        XTA-001.psd1's header comment for why.

        Simplified from the matrix's full design in ways this project owns and documents rather
        than silently assumes:
          1. "Privileged resource role" is defined only via AadGroup-origin roles correlated
             against this project's existing Group.isAssignableToRole and AzureRoleAssignment
             evidence (the matrix's own recommended resolution to its open question on this
             point). AadApplication-origin (app role) privilege classification is not
             implemented -- a real, undecided gap, not a silent narrowing.
          2. Does not implement the licensing-gate NotApplicable distinction (Entra ID
             Governance/Entra Suite/P2) -- license state is not currently collected evidence,
             same boundary AR-001/AR-002 already have.
          3. Resolves an internal inconsistency between the matrix's own "Applicability" text
             (implies one NotApplicable result per non-privileged package) and its "Expected
             result semantics" text (implies no result at all for a non-privileged package) by
             following the latter, plus a single tenant-scoped NotApplicable when NO package
             anywhere is privileged -- see the evaluator's own DESCRIPTION for the full reasoning.
    #>
    controlId   = 'EM-001'
    version     = '1.0.0'
    title       = 'Access Package Grants Privileged Resource Access Through an Insufficiently Vetted Policy'
    description = 'For each access package with at least one privileged (role-assignable or Azure-role-bearing group) resource role, checks whether every attached assignment policy either requires approval or is narrowly scoped, rather than allowing broad, unapproved self-service access to that privileged target.'
    rationale   = 'A package''s actual risk is governed by whichever policy a given requester matches, so one lax policy undermines the resource''s protection regardless of how strict any other policy on the same package is -- the same "weakest composed policy governs" failure mode this project already applies to Conditional Access and cross-tenant access, now confirmed for entitlement management by Microsoft''s own documented use of access packages to grant Entra-role and Azure-role-bearing group membership.'
    severity    = 3
    category    = 'Entitlement Management'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AccessPackage', 'AccessPackageAssignmentPolicy', 'Group', 'AzureRoleAssignment')
    requiredPermissions     = @(
        @{ scope = 'EntitlementManagement.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per access package with at least one privileged resource role. A single tenant-scoped NotApplicable result is produced if no access package anywhere has a privileged resource role.'

    reasonCodes = @(
        @{ code = 'EM001-AUTO-ASSIGNMENT-NO-APPROVAL'; resultStatus = 'Fail'; description = 'A privileged-resource package has an auto-assignment policy (automaticRequestSettings present), which has no approval step at all.' }
        @{ code = 'EM001-BROAD-SCOPE-NO-APPROVAL';     resultStatus = 'Fail'; description = 'A privileged-resource package has a request-based policy with approval not required (isApprovalRequiredForAdd=false) and a broad allowedTargetScope.' }
        @{ code = 'EM001-ADEQUATELY-VETTED';           resultStatus = 'Pass'; description = 'A privileged-resource package''s every attached policy either requires approval or is narrowly scoped.' }
        @{ code = 'EM001-NO-PRIVILEGED-RESOURCES';     resultStatus = 'NotApplicable'; description = 'No access package''s resource roles resolve to a role-assignable or Azure-role-bearing group.' }
        @{ code = 'EM001-EVIDENCE-NOT-COLLECTED';      resultStatus = 'NotEvaluated'; description = 'AccessPackage/AccessPackageAssignmentPolicy evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'EM001-EVALUATOR-ERROR';             resultStatus = 'Error'; description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per access package with at least one privileged resource role, checked in priority order (auto-assignment before broad-scope-no-approval, matching the matrix''s own "maximally permissive case" ordering); Fail if either condition applies to any attached policy, Pass otherwise (including a privileged package with zero attached policies, vacuously). A single tenant-scoped NotApplicable result is produced instead if no package anywhere is privileged. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself.'

    evaluatorFunctionName  = 'Test-EntraPostureAccessPackagePrivilegedPolicyVettingControl'
    evidenceRedactionPolicy = 'None'

    remediation = 'Require approval (specific approvers, not self-approval) on every policy attached to a package containing privileged resource roles; remove or narrow any auto-assignment policy targeting such a package; narrow allowedTargetScope to the specific population that legitimately needs request access rather than all directory/all external users.'

    references = @(
        'https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview'
        'https://learn.microsoft.com/en-us/graph/api/resources/accesspackage?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/accesspackageresourcerolescope?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/accesspackageresource?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/accesspackageassignmentpolicy?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/graph/api/resources/accesspackageassignmentapprovalsettings?view=graph-rest-1.0'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Clean-room control authored directly from Microsoft Graph's accessPackage/accessPackageResourceRoleScope/accessPackageAssignmentPolicy/accessPackageAssignmentApprovalSettings resource documentation (all six references above fetched live during this build-order item) and 15-feature-parity-matrix.md section 8's EM-001 design, narrowed per this file's own header comment (AadGroup-origin privilege classification only, no license gate, and a resolved applicability inconsistency). Per docs/VNext.md's review-not-reuse policy: no external reference-repo source was read for this control's logic. Admitted into v1 scope by the deviation record in 00-open-questions.md item 28."
    }

    externalMappings = @()

    baselineDependency = @{
        documentationUrl  = 'https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview'
        asOfDate          = '2026-08-07'
        citationStrength  = 'Inference'
    }
}
