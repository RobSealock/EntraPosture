@{
    <#
        VNext build order item 2, the 109-row backlog completion pass (2026-08-08). Keys
        deliberately camelCase -- see XTA-001.psd1's header comment for why.
    #>
    controlId   = 'USR-002'
    version     = '1.0.0'
    title       = 'Non-Admin Users Can Create New Tenants'
    description = 'Checks the tenant''s AuthorizationPolicy.defaultUserRolePermissions.allowedToCreateTenants setting.'
    rationale   = 'A user-created tenant is outside existing governance -- it has no Conditional Access, no monitoring, no admin oversight -- and can be used to stage attacks or exfiltrate data with no security controls in place.'
    severity    = 1
    category    = 'Users'
    ownership   = 'Security Ops'

    requiredEvidenceDomains = @('AuthorizationPolicy')
    requiredPermissions     = @(
        @{ scope = 'Policy.Read.All'; confirmed = $true }
    )

    applicability = 'Evaluated once per AuthorizationPolicy entity (in practice, exactly one). NotApplicable (a single tenant-scoped result) if the singleton is missing from evidence entirely.'

    reasonCodes = @(
        @{ code = 'USR-002-NON-ADMIN-TENANT-CREATION-ALLOWED';    resultStatus = 'Fail';         description = 'Non-admin users are allowed to create new Entra ID tenants.' }
        @{ code = 'USR-002-NON-ADMIN-TENANT-CREATION-RESTRICTED'; resultStatus = 'Pass';        description = 'Non-admin users are not allowed to create new Entra ID tenants.' }
        @{ code = 'USR-002-NO-POLICY-FOUND';                      resultStatus = 'NotApplicable'; description = 'No AuthorizationPolicy entity was present in the evidence set.' }
        @{ code = 'USR-002-EVIDENCE-NOT-COLLECTED';               resultStatus = 'NotEvaluated'; description = 'AuthorizationPolicy evidence was not fully collected for this snapshot.' }
        @{ code = 'USR-002-EVALUATOR-ERROR';                      resultStatus = 'Error';        description = 'The evaluator function threw while processing otherwise-available evidence.' }
    )

    expectedResultSemantics = 'One result per AuthorizationPolicy entity (in practice exactly one). Fail if allowedToCreateTenants is true, Pass if false. NotEvaluated/Error are assigned by the orchestration layer.'

    evaluatorFunctionName  = 'Test-EntraPostureNonAdminTenantCreationControl'
    evidenceRedactionPolicy = 'Identifiers'

    remediation = 'Disable "Restrict non-admin users from creating tenants" exceptions -- set allowedToCreateTenants to false in the tenant''s default user role permissions.'

    references = @(
        'https://learn.microsoft.com/en-us/graph/api/resources/defaultuserrolepermissions?view=graph-rest-1.0'
        'https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions#restrict-member-users-default-permissions'
    )

    provenance = @{
        disposition   = 'Reimplement'
        sourceProject = $null
        notes         = 'Control ID/title reused from 15-feature-parity-matrix.md section 3.3 for tracking continuity, not a port of EntraFalcon''s own source logic. allowedToCreateTenants confirmed present on the same default GET /v1.0/policies/authorizationPolicy response already used by COL-001/002/USR-001/GRP-001, re-fetched 2026-08-08.'
    }

    externalMappings = @(
        @{ framework = 'EntraFalcon'; identifier = 'USR-002' }
    )

    baselineDependency = $null
}
