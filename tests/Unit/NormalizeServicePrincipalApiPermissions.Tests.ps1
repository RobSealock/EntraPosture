#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2, new-evidence phase (the "Extensive API Privileges" architecture-
    fork item, resolved 2026-08-08): ConvertTo-EntraPostureServicePrincipalApiPermissionsEntity,
    field shapes confirmed directly against the live "List appRoleAssignments granted to a
    service principal" and "List a service principal's oauth2PermissionGrants" Graph reference
    pages (re-fetched 2026-08-08) -- see the normalizer's own DESCRIPTION.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeServicePrincipalApiPermissions.ps1')

    function script:ConvertTo-TestOrderedDictionary {
        param([Parameter(Mandatory)][string]$Json)
        return ConvertFrom-EntraPostureJson -Json $Json
    }
}

Describe 'ConvertTo-EntraPostureServicePrincipalApiPermissionsEntity' {
    It 'extracts deduplicated appRoleIds and delegated scopes' {
        $appRoleAssignments = @(
            (ConvertTo-TestOrderedDictionary -Json '{ "appRoleId": "role-1", "resourceDisplayName": "Microsoft Graph" }'),
            (ConvertTo-TestOrderedDictionary -Json '{ "appRoleId": "role-2", "resourceDisplayName": "Microsoft Graph" }'),
            (ConvertTo-TestOrderedDictionary -Json '{ "appRoleId": "role-1", "resourceDisplayName": "Microsoft Graph" }')
        )
        $oauth2Grants = @(
            (ConvertTo-TestOrderedDictionary -Json '{ "scope": "Mail.Read Mail.Send" }'),
            (ConvertTo-TestOrderedDictionary -Json '{ "scope": "Mail.Read" }')
        )
        $entity = ConvertTo-EntraPostureServicePrincipalApiPermissionsEntity -ServicePrincipalEntityId 'sp-1' `
            -RawAppRoleAssignments $appRoleAssignments -RawOauth2PermissionGrants $oauth2Grants `
            -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.entityId | Should -Be 'sp-1'
        $entity.entityType | Should -Be 'ServicePrincipalApiPermissions'
        @($entity.properties.applicationPermissionAppRoleIds) | Should -Be @('role-1', 'role-2')
        @($entity.properties.delegatedPermissionScopes) | Should -Be @('Mail.Read', 'Mail.Send')
    }

    It 'produces empty arrays, not null, when no grants are supplied' {
        $entity = ConvertTo-EntraPostureServicePrincipalApiPermissionsEntity -ServicePrincipalEntityId 'sp-2' `
            -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        @($entity.properties.applicationPermissionAppRoleIds).Count | Should -Be 0
        @($entity.properties.delegatedPermissionScopes).Count | Should -Be 0
    }
}
