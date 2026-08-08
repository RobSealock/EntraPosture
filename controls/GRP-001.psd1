@{
    <#
        Fixed-state predicate control (VNext build-order item 2, same "first slice" batch as
        USR-001.psd1 -- see that file's header comment for the shared reasoning). Control
        ID/title continuity from 15-feature-parity-matrix.md section 3.3's EntraFalcon-derived
        canonical finding registry (GRP-001, "Security Group Creation Not Restricted", severity
        2). Keys are deliberately camelCase -- see XTA-001.psd1's header comment for why.

        Reads the sibling field to USR-001's allowedToCreateApps on the same already-collected
        AuthorizationPolicy entity (src/Normalization/NormalizeTenantPolicies.ps1) --
        allowedToCreateSecurityGroups -- so this control also needed no new evidence domain, no
        new collector, and no normalizer change.

        Note this is control ID GRP-001, distinct from GRP-005 (controls/GRP-005.psd1, "Weak
        Protection of Sensitive Groups" / excessive transitive membership on role-assignable
        groups) -- different EntraFalcon finding, different evidence, different check.
    #>
    controlId   = 'GRP-001'
    version     = '1.0.0'
    title       = 'Non-Admin Users Can Create Security Groups by Default'
    description = "Checks the tenant's authorizationPolicy.defaultUserRolePermissions.allowedToCreateSecurityGroups setting, which controls whether users in the default (non-admin) role can create new security groups in Entra ID without any administrative role."
    rationale   = 'Security groups are a first-class access-control primitive in Entra ID and Azure -- they can be nested into role-assignable groups, referenced directly in Conditional Access policy scoping, and used to grant application/resource access. Unrestricted self-service creation means any user can create a group with itself as owner and use it as an access-grant vehicle with no administrative review of why the group exists or who ends up in it, defeating the reviewability every other group-related control in this project''s registry (GRP-005 among them) assumes a curated group population provides. Microsoft Graph documents this permission as tenant-wide and on by default (the defaultUserRolePermissions JSON representation states allowedToCreateSecurityGroups defaults to true), and separately documents a dedicated setting to restrict it to specific administrative roles instead.'
    severity    = 2
    category    = 'Groups'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AuthorizationPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable when the tenant''s authorizationPolicy was collected -- every tenant has exactly one.'

    reasonCodes = @(
        @{ code = 'GRP-001-GROUP-CREATION-UNRESTRICTED'; resultStatus = 'Fail';         description = 'allowedToCreateSecurityGroups is true, or the field is absent from evidence (Microsoft''s own documented default is true, so absence is treated the same as an explicit true, not as restricted).' }
        @{ code = 'GRP-001-GROUP-CREATION-RESTRICTED';   resultStatus = 'Pass';         description = 'allowedToCreateSecurityGroups is explicitly false.' }
        @{ code = 'GRP-001-NO-POLICY-FOUND';             resultStatus = 'NotApplicable'; description = 'No AuthorizationPolicy entity was present in the evidence set (unexpected in a real tenant, but handled defensively).' }
        @{ code = 'GRP-001-EVIDENCE-NOT-COLLECTED';      resultStatus = 'NotEvaluated'; description = 'AuthorizationPolicy evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'GRP-001-EVALUATOR-ERROR';             resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Fail when allowedToCreateSecurityGroups is true or absent from evidence (absence is deliberately treated as the documented permissive default, not as restricted -- see GRP-001-GROUP-CREATION-UNRESTRICTED''s own description). Pass only when the field is explicitly false. NotApplicable only if no AuthorizationPolicy entity exists in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself (engineering plan section 9.2).'

    evaluatorFunctionName  = 'Test-EntraPostureSecurityGroupCreationRestrictionControl'
    evidenceRedactionPolicy = 'None'

    remediation = "Set defaultUserRolePermissions.allowedToCreateSecurityGroups to false (Microsoft Entra admin center: Identity > Groups > General settings > 'Users can create security groups' > No, or the equivalent Group settings menu), then grant group-creation ability through the Groups Administrator role or an owned-group delegation model instead of leaving it open to every user."

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/defaultuserrolepermissions?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Control ID/title reused from 15-feature-parity-matrix.md section 3.3's EntraFalcon-derived canonical finding registry (GRP-001, ""Security Group Creation Not Restricted"") for tracking continuity. Per docs/VNext.md's 'reviewing external reference repos' policy (2026-08-07): only the finding registry's own title/severity/category listing was used for this cross-check, not EntraFalcon's check_Tenant.psm1 source logic, which was not read for this pass -- this control's field-level logic (allowedToCreateSecurityGroups, the false-only-is-restricted direction, and treating an absent field as the documented permissive default rather than as restricted) was authored directly and independently from the Microsoft Graph API reference cited below."
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'GRP-001' }
    )

    baselineDependency = @{
        documentationUrl  = 'https://learn.microsoft.com/en-us/graph/api/resources/defaultuserrolepermissions?view=graph-rest-1.0'
        asOfDate          = '2026-08-07'
        citationStrength  = 'ApiExampleResponse'
    }
}
