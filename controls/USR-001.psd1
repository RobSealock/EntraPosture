@{
    <#
        Fixed-state predicate control (VNext build-order item 2: "a first slice of the remaining
        ~150 matrix rows -- rows that need zero new evidence domains or collectors"). Control
        ID/title continuity from 15-feature-parity-matrix.md section 3.3's EntraFalcon-derived
        canonical finding registry (USR-001, "App Creation Not Restricted", severity 2) -- see
        this file's provenance.notes for what "continuity" does and doesn't mean here. Keys are
        deliberately camelCase -- see XTA-001.psd1's header comment for why.

        Reads a field this project's AuthorizationPolicy evidence already captures for AC-001
        (src/Normalization/NormalizeTenantPolicies.ps1) -- allowedToCreateApps -- so this control
        needed no new evidence domain, no new collector, and no normalizer change: exactly the
        kind of "first slice" row VNext.md's build order describes.
    #>
    controlId   = 'USR-001'
    version     = '1.0.0'
    title       = 'Non-Admin Users Can Register Application Registrations by Default'
    description = "Checks the tenant's authorizationPolicy.defaultUserRolePermissions.allowedToCreateApps setting, which controls whether users in the default (non-admin) role can register new applications in Entra ID without any administrative role."
    rationale   = 'Self-service application registration lets any authenticated user create an application object, become its owner, request OAuth permissions, and generate client secrets or configure redirect URIs -- exactly the foothold illicit-consent-grant and OAuth-phishing techniques rely on an attacker (or a compromised low-privilege account) being able to create. Microsoft Graph documents this permission as tenant-wide and on by default (the defaultUserRolePermissions JSON representation states allowedToCreateApps defaults to true), and separately documents a dedicated setting to restrict it -- narrowing self-service registration to a curated Application Developer role rather than every user -- without blocking legitimate development work.'
    severity    = 2
    category    = 'Users'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AuthorizationPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Always applicable when the tenant''s authorizationPolicy was collected -- every tenant has exactly one.'

    reasonCodes = @(
        @{ code = 'USR-001-APP-CREATION-UNRESTRICTED'; resultStatus = 'Fail';         description = 'allowedToCreateApps is true, or the field is absent from evidence (Microsoft''s own documented default is true, so absence is treated the same as an explicit true, not as restricted).' }
        @{ code = 'USR-001-APP-CREATION-RESTRICTED';   resultStatus = 'Pass';         description = 'allowedToCreateApps is explicitly false.' }
        @{ code = 'USR-001-NO-POLICY-FOUND';           resultStatus = 'NotApplicable'; description = 'No AuthorizationPolicy entity was present in the evidence set (unexpected in a real tenant, but handled defensively).' }
        @{ code = 'USR-001-EVIDENCE-NOT-COLLECTED';    resultStatus = 'NotEvaluated'; description = 'AuthorizationPolicy evidence was not fully collected for this snapshot (coverage.json evidenceStatus was not Collected).' }
        @{ code = 'USR-001-EVALUATOR-ERROR';           resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'Fail when allowedToCreateApps is true or absent from evidence (absence is deliberately treated as the documented permissive default, not as restricted -- see USR-001-APP-CREATION-UNRESTRICTED''s own description). Pass only when the field is explicitly false. NotApplicable only if no AuthorizationPolicy entity exists in evidence at all. NotEvaluated/Error are assigned by the orchestration layer, never by the evaluator function itself (engineering plan section 9.2).'

    evaluatorFunctionName  = 'Test-EntraPostureAppCreationRestrictionControl'
    evidenceRedactionPolicy = 'None'

    remediation = "Set defaultUserRolePermissions.allowedToCreateApps to false (Microsoft Entra admin center: Identity > Users > User settings > 'Users can register applications' > No), then grant the Application Developer role to specific individuals who need self-service registration instead of leaving it open to every user."

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/defaultuserrolepermissions?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = "Control ID/title reused from 15-feature-parity-matrix.md section 3.3's EntraFalcon-derived canonical finding registry (USR-001, ""App Creation Not Restricted"") for tracking continuity. Per docs/VNext.md's 'reviewing external reference repos' policy (2026-08-07): only the finding registry's own title/severity/category listing was used for this cross-check, not EntraFalcon's check_Tenant.psm1 source logic, which was not read for this pass -- this control's field-level logic (allowedToCreateApps, the false-only-is-restricted direction, and treating an absent field as the documented permissive default rather than as restricted) was authored directly and independently from the Microsoft Graph API reference cited below."
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'USR-001' }
    )

    baselineDependency = @{
        documentationUrl  = 'https://learn.microsoft.com/en-us/graph/api/resources/defaultuserrolepermissions?view=graph-rest-1.0'
        asOfDate          = '2026-08-07'
        citationStrength  = 'ApiExampleResponse'
    }
}
