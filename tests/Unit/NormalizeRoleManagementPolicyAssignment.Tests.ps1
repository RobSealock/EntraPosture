#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 7: ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity, field
    shapes confirmed directly against Microsoft Graph's unifiedRoleManagementPolicy/
    PolicyAssignment/PolicyRule resource documentation (re-fetched 2026-08-07).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeRoleManagementPolicyAssignment.ps1')

    function script:ConvertTo-TestOrderedDictionary {
        param([Parameter(Mandatory)][string]$Json)
        return ConvertFrom-EntraPostureJson -Json $Json
    }

    # Mirrors Microsoft's own documented example shape: EndUser/Assignment-level Enablement,
    # Expiration, Approval, and AuthenticationContext rules, plus Admin/Eligibility-level rules of
    # the same types that must NOT be picked up (different target).
    $script:FullRawAssignmentJson = @'
{
  "id": "DirectoryRole_t_p_62e90394-69f5-4237-9190-012177145e10",
  "policyId": "DirectoryRole_t_p",
  "scopeId": "/", "scopeType": "DirectoryRole",
  "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
  "policy": {
    "id": "DirectoryRole_t_p",
    "rules": [
      {
        "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule",
        "id": "Enablement_Admin_Eligibility",
        "enabledRules": [],
        "target": { "caller": "Admin", "level": "Eligibility" }
      },
      {
        "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule",
        "id": "Enablement_EndUser_Assignment",
        "enabledRules": ["MultiFactorAuthentication", "Justification"],
        "target": { "caller": "EndUser", "level": "Assignment" }
      },
      {
        "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule",
        "id": "Expiration_EndUser_Assignment",
        "isExpirationRequired": true,
        "maximumDuration": "PT8H",
        "target": { "caller": "EndUser", "level": "Assignment" }
      },
      {
        "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule",
        "id": "Approval_EndUser_Assignment",
        "target": { "caller": "EndUser", "level": "Assignment" },
        "setting": { "isApprovalRequired": true }
      },
      {
        "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule",
        "id": "AuthenticationContext_EndUser_Assignment",
        "isEnabled": true,
        "claimValue": "c1",
        "target": { "caller": "EndUser", "level": "Assignment" }
      },
      {
        "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule",
        "id": "Notification_Admin_EndUser_Assignment",
        "isDefaultRecipientsEnabled": false, "notificationRecipients": [],
        "target": { "caller": "EndUser", "level": "Assignment" }
      },
      {
        "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule",
        "id": "Enablement_Admin_Assignment",
        "enabledRules": ["Justification"],
        "target": { "caller": "Admin", "level": "Assignment" }
      },
      {
        "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule",
        "id": "Expiration_Admin_Assignment",
        "isExpirationRequired": false,
        "maximumDuration": "P180D",
        "target": { "caller": "Admin", "level": "Assignment" }
      }
    ]
  }
}
'@

    # Same shape, but with the EndUser/Assignment notification rule actually enabled via an
    # explicit recipient (not the default-recipients flag) -- proves the aggregate checks both
    # paths, not just isDefaultRecipientsEnabled.
    $script:NotificationEnabledRawAssignmentJson = @'
{
  "id": "a2", "roleDefinitionId": "role-2",
  "policy": { "id": "p2", "rules": [
    {
      "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule",
      "id": "Notification_Requestor_EndUser_Assignment",
      "isDefaultRecipientsEnabled": false, "notificationRecipients": ["secops@contoso.com"],
      "target": { "caller": "EndUser", "level": "Assignment" }
    }
  ] }
}
'@
}

Describe 'ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity' {
    It 'maps roleDefinitionId and every EndUser/Assignment-level rule field' {
        $raw = ConvertTo-TestOrderedDictionary -Json $script:FullRawAssignmentJson
        $entity = ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity -RawAssignment $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.entityType | Should -Be 'RoleManagementPolicyAssignment'
        $entity.properties.roleDefinitionId | Should -Be '62e90394-69f5-4237-9190-012177145e10'
        @($entity.properties.enabledRules) | Should -Be @('MultiFactorAuthentication', 'Justification')
        $entity.properties.isExpirationRequired | Should -BeTrue
        $entity.properties.maximumDuration | Should -Be 'PT8H'
        $entity.properties.approvalRequired | Should -BeTrue
        $entity.properties.authenticationContextEnabled | Should -BeTrue
        $entity.properties.authenticationContextClaimValue | Should -Be 'c1'
    }

    It 'maps Admin/Assignment-level rules separately from EndUser/Assignment (VNext build order item 8)' {
        $raw = ConvertTo-TestOrderedDictionary -Json $script:FullRawAssignmentJson
        $entity = ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity -RawAssignment $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        @($entity.properties.adminAssignmentEnabledRules) | Should -Be @('Justification')
        $entity.properties.adminAssignmentIsExpirationRequired | Should -BeFalse
        $entity.properties.adminAssignmentMaximumDuration | Should -Be 'P180D'
        # Confirms Admin/Assignment and EndUser/Assignment are genuinely independent fields, not
        # the same rule read twice -- the EndUser/Assignment expiration IS required (PT8H), the
        # Admin/Assignment one is NOT (permanent active assignment allowed).
        $entity.properties.isExpirationRequired | Should -BeTrue
    }

    It 'defaults Admin/Assignment fields to empty/null when no such rule is present' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{"id":"a1","roleDefinitionId":"r1","policy":{"id":"p1","rules":[]}}'
        $entity = ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity -RawAssignment $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        @($entity.properties.adminAssignmentEnabledRules).Count | Should -Be 0
        $entity.properties.adminAssignmentIsExpirationRequired | Should -BeNullOrEmpty
        $entity.properties.adminAssignmentMaximumDuration | Should -BeNullOrEmpty
    }

    It 'activationNotificationEnabled is false when the only EndUser/Assignment notification rule has no recipients configured' {
        $raw = ConvertTo-TestOrderedDictionary -Json $script:FullRawAssignmentJson
        $entity = ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity -RawAssignment $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.activationNotificationEnabled | Should -BeFalse
    }

    It 'activationNotificationEnabled is true when a notification rule has an explicit recipient, even with isDefaultRecipientsEnabled=false' {
        $raw = ConvertTo-TestOrderedDictionary -Json $script:NotificationEnabledRawAssignmentJson
        $entity = ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity -RawAssignment $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.activationNotificationEnabled | Should -BeTrue
    }

    It 'ignores Admin/Eligibility-level rules of the same types -- only EndUser/Assignment counts' {
        $raw = ConvertTo-TestOrderedDictionary -Json $script:FullRawAssignmentJson
        $entity = ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity -RawAssignment $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        # The Admin/Eligibility EnablementRule has an empty enabledRules array; if that one were
        # picked up instead of the EndUser/Assignment one, this would be empty, not populated.
        @($entity.properties.enabledRules).Count | Should -Be 2
    }

    It 'defaults authenticationContextEnabled to $false and claimValue to $null when no AuthenticationContextRule is present at all' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{"id":"a1","roleDefinitionId":"r1","policy":{"id":"p1","rules":[]}}'
        $entity = ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity -RawAssignment $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.authenticationContextEnabled | Should -BeFalse
        $entity.properties.authenticationContextClaimValue | Should -BeNullOrEmpty
        @($entity.properties.enabledRules).Count | Should -Be 0
    }

    It 'throws when the raw record has no id' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{"roleDefinitionId":"r1"}'
        { ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity -RawAssignment $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z' } | Should -Throw '*no id*'
    }

    It 'throws when the raw record has no roleDefinitionId' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{"id":"a1"}'
        { ConvertTo-EntraPostureRoleManagementPolicyAssignmentEntity -RawAssignment $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z' } | Should -Throw '*roleDefinitionId*'
    }
}
