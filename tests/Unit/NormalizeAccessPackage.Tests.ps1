#Requires -Version 7.4
#Requires -Modules Pester

<#
    v.next build order item 11 (EM-001/EM-002): ConvertTo-EntraPostureAccessPackageEntity,
    ConvertTo-EntraPostureAccessPackageAssignmentPolicyEntity,
    ConvertTo-EntraPostureAccessPackageAssignmentEntity. Field shapes confirmed live against
    Microsoft Graph's accessPackage/accessPackageResourceRoleScope/
    accessPackageAssignmentPolicy/accessPackageAssignmentApprovalSettings/expirationPattern/
    accessPackageAssignment resource documentation (fetched during this build-order item).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeAccessPackage.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeAccessPackageAssignmentPolicy.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeAccessPackageAssignment.ps1')

    function script:ConvertTo-TestOrderedDictionary {
        param([Parameter(Mandatory)][string]$Json)
        return ConvertFrom-EntraPostureJson -Json $Json
    }
}

Describe 'ConvertTo-EntraPostureAccessPackageEntity' {
    It 'maps displayName/description/isHidden and flattens resourceRoleScopes into resourceRoles' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{ "id": "pkg-1", "displayName": "Finance Access", "description": "desc", "isHidden": false,
  "resourceRoleScopes": [
    { "id": "rrs-1", "role": { "id": "r1", "displayName": "Member", "originSystem": "AadGroup", "originId": "group-1" }, "scope": { "id": "s1", "displayName": "Root" } },
    { "id": "rrs-2", "role": { "id": "r2", "displayName": "Reader", "originSystem": "SharePointOnline", "originId": "site-1" }, "scope": { "id": "s2", "displayName": "Root" } }
  ] }
'@
        $entity = ConvertTo-EntraPostureAccessPackageEntity -RawPackage $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.entityId | Should -Be 'pkg-1'
        $entity.entityType | Should -Be 'AccessPackage'
        $entity.displayName | Should -Be 'Finance Access'
        $entity.properties.isHidden | Should -BeFalse
        $entity.properties.resourceRoles.Count | Should -Be 2
        $entity.properties.resourceRoles[0].originSystem | Should -Be 'AadGroup'
        $entity.properties.resourceRoles[0].originId | Should -Be 'group-1'
        $entity.properties.resourceRoles[1].originSystem | Should -Be 'SharePointOnline'
    }

    It 'returns an empty resourceRoles array when resourceRoleScopes is absent' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "id": "pkg-2" }'
        $entity = ConvertTo-EntraPostureAccessPackageEntity -RawPackage $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        @($entity.properties.resourceRoles).Count | Should -Be 0
    }

    It 'throws when the raw record has no id' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "displayName": "No ID" }'
        { ConvertTo-EntraPostureAccessPackageEntity -RawPackage $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z' } | Should -Throw '*no id*'
    }
}

Describe 'ConvertTo-EntraPostureAccessPackageAssignmentPolicyEntity' {
    It 'marks isAutoAssignment true and leaves isApprovalRequiredForAdd null when automaticRequestSettings is present' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "id": "pol-1", "displayName": "Auto", "allowedTargetScope": "allDirectoryUsers", "automaticRequestSettings": {} }'
        $entity = ConvertTo-EntraPostureAccessPackageAssignmentPolicyEntity -RawPolicy $raw -AccessPackageId 'pkg-1' -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.isAutoAssignment | Should -BeTrue
        $entity.properties.isApprovalRequiredForAdd | Should -BeNullOrEmpty
        $entity.properties.accessPackageId | Should -Be 'pkg-1'
    }

    It 'maps isApprovalRequiredForAdd (the exact Microsoft field name) and expiration fields for a request-based policy' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{ "id": "pol-2", "displayName": "Request-based", "allowedTargetScope": "specificDirectoryUsers",
  "requestApprovalSettings": { "isApprovalRequiredForAdd": false, "isApprovalRequiredForUpdate": false, "isRequestorJustificationRequired": false },
  "expiration": { "type": "noExpiration" } }
'@
        $entity = ConvertTo-EntraPostureAccessPackageAssignmentPolicyEntity -RawPolicy $raw -AccessPackageId 'pkg-1' -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.isAutoAssignment | Should -BeFalse
        $entity.properties.isApprovalRequiredForAdd | Should -BeFalse
        $entity.properties.expirationType | Should -Be 'noExpiration'
    }

    It 'throws when the raw record has no id' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "displayName": "No ID" }'
        { ConvertTo-EntraPostureAccessPackageAssignmentPolicyEntity -RawPolicy $raw -AccessPackageId 'pkg-1' -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z' } | Should -Throw '*no id*'
    }
}

Describe 'ConvertTo-EntraPostureAccessPackageAssignmentEntity: field mapping and redaction' {
    It 'maps state/status/expiredDateTime and accessPackageId from the expanded accessPackage navigation property' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "id": "asg-1", "state": "expired", "status": "ExpiredNotificationTriggered", "expiredDateTime": "2026-01-01T00:00:00Z", "accessPackage": { "id": "pkg-1", "displayName": "Finance Access" } }'
        $entity = ConvertTo-EntraPostureAccessPackageAssignmentEntity -RawAssignment $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.entityId | Should -Be 'asg-1'
        $entity.displayName | Should -BeNullOrEmpty
        $entity.properties.accessPackageId | Should -Be 'pkg-1'
        $entity.properties.state | Should -Be 'expired'
        $entity.properties.expiredDateTime | Should -Be '2026-01-01T00:00:00Z'
    }

    It 'never persists any principal-identifying field, even if planted in the raw record' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "id": "asg-2", "state": "delivered", "accessPackage": { "id": "pkg-1" }, "target": { "objectId": "user-secret-123", "principalName": "alice@contoso.com" } }'
        $entity = ConvertTo-EntraPostureAccessPackageAssignmentEntity -RawAssignment $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $propertyKeys = @($entity.properties.Keys)
        $propertyKeys | Should -Not -Contain 'target'
        $json = ConvertTo-EntraPostureCanonicalJson -InputObject $entity
        $json | Should -Not -Match 'user-secret-123'
        $json | Should -Not -Match 'alice@contoso.com'
    }

    It 'throws when the raw record has no id' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "state": "delivered" }'
        { ConvertTo-EntraPostureAccessPackageAssignmentEntity -RawAssignment $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z' } | Should -Throw '*no id*'
    }
}
