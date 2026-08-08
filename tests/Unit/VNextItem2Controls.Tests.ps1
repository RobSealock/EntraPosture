#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2 (docs/VNext.md, 00-open-questions.md section 19): "a first slice of
    the remaining ~150 matrix rows -- rows that need zero new evidence domains or collectors."
    USR-001 and GRP-001 both read fields already captured on the AuthorizationPolicy entity
    (src/Normalization/NormalizeTenantPolicies.ps1) for AC-001 -- no collector or normalizer
    change was needed for either. Same lightweight evaluator-direct-against-a-hand-built-
    evidence-directory pattern as tests/Unit/Phase7Controls.Tests.ps1 (this file intentionally
    duplicates its small helper functions rather than sharing them across files, matching this
    project's per-file "dot-source exactly what you need" test convention).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateAppCreationRestriction.ps1',
        'src/Controls/EvaluateSecurityGroupCreationRestriction.ps1',
        'src/Controls/EvaluateGuestInviteRestriction.ps1',
        'src/Controls/EvaluateAdminSelfServicePasswordReset.ps1',
        'src/Controls/EvaluateNonAdminTenantCreation.ps1',
        'src/Controls/EvaluateBitlockerKeyReadAccess.ps1',
        'src/Controls/EvaluateUserAppConsent.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "vnext-item2-controls-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestEntity {
        param([string]$EntityId, [string]$EntityType, [string]$DisplayName = $null, [System.Collections.Specialized.OrderedDictionary]$Properties)
        return [ordered]@{
            entityId = $EntityId; entityType = $EntityType; tenantScope = 't1'
            displayName = $DisplayName; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
            sourceEndpoint = 'x'; properties = $Properties; redacted = $false
        }
    }
}

Describe 'USR-001: Test-EntraPostureAppCreationRestrictionControl' {
    It 'Fails when allowedToCreateApps is true' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                allowInvitesFrom = 'everyone'; allowedToCreateApps = $true; allowedToCreateSecurityGroups = $false; allowedToReadOtherUsers = $true
                permissionGrantPoliciesAssigned = @()
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAppCreationRestrictionControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'USR-001-APP-CREATION-UNRESTRICTED'
    }

    It 'Fails when allowedToCreateApps is absent from evidence (treated as the documented permissive default, not as restricted)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                allowInvitesFrom = 'everyone'; allowedToCreateApps = $null; allowedToCreateSecurityGroups = $false; allowedToReadOtherUsers = $true
                permissionGrantPoliciesAssigned = @()
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAppCreationRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'USR-001-APP-CREATION-UNRESTRICTED'
    }

    It 'Passes when allowedToCreateApps is explicitly false' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                allowInvitesFrom = 'everyone'; allowedToCreateApps = $false; allowedToCreateSecurityGroups = $false; allowedToReadOtherUsers = $true
                permissionGrantPoliciesAssigned = @()
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAppCreationRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'USR-001-APP-CREATION-RESTRICTED'
    }

    It 'Reports NotApplicable when no AuthorizationPolicy entity exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAppCreationRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'USR-001-NO-POLICY-FOUND'
    }
}

Describe 'GRP-001: Test-EntraPostureSecurityGroupCreationRestrictionControl' {
    It 'Fails when allowedToCreateSecurityGroups is true' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                allowInvitesFrom = 'everyone'; allowedToCreateApps = $false; allowedToCreateSecurityGroups = $true; allowedToReadOtherUsers = $true
                permissionGrantPoliciesAssigned = @()
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureSecurityGroupCreationRestrictionControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'GRP-001-GROUP-CREATION-UNRESTRICTED'
    }

    It 'Fails when allowedToCreateSecurityGroups is absent from evidence (treated as the documented permissive default, not as restricted)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                allowInvitesFrom = 'everyone'; allowedToCreateApps = $false; allowedToCreateSecurityGroups = $null; allowedToReadOtherUsers = $true
                permissionGrantPoliciesAssigned = @()
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureSecurityGroupCreationRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'GRP-001-GROUP-CREATION-UNRESTRICTED'
    }

    It 'Passes when allowedToCreateSecurityGroups is explicitly false' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                allowInvitesFrom = 'everyone'; allowedToCreateApps = $false; allowedToCreateSecurityGroups = $false; allowedToReadOtherUsers = $true
                permissionGrantPoliciesAssigned = @()
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureSecurityGroupCreationRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'GRP-001-GROUP-CREATION-RESTRICTED'
    }

    It 'Reports NotApplicable when no AuthorizationPolicy entity exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureSecurityGroupCreationRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'GRP-001-NO-POLICY-FOUND'
    }
}

Describe 'COL-002: Test-EntraPostureGuestInviteRestrictionControl' {
    It 'Fails when allowInvitesFrom is everyone' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                allowInvitesFrom = 'everyone'; allowedToCreateApps = $false; allowedToCreateSecurityGroups = $false; allowedToReadOtherUsers = $true
                permissionGrantPoliciesAssigned = @()
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureGuestInviteRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'COL-002-GUEST-INVITE-UNRESTRICTED'
    }

    It 'Fails when allowInvitesFrom is adminsGuestInvitersAndAllMembers' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                allowInvitesFrom = 'adminsGuestInvitersAndAllMembers'; allowedToCreateApps = $false; allowedToCreateSecurityGroups = $false; allowedToReadOtherUsers = $true
                permissionGrantPoliciesAssigned = @()
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureGuestInviteRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
    }

    It 'Passes when allowInvitesFrom is adminsAndGuestInviters' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                allowInvitesFrom = 'adminsAndGuestInviters'; allowedToCreateApps = $false; allowedToCreateSecurityGroups = $false; allowedToReadOtherUsers = $true
                permissionGrantPoliciesAssigned = @()
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureGuestInviteRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'COL-002-GUEST-INVITE-RESTRICTED'
    }

    It 'Passes when allowInvitesFrom is none' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                allowInvitesFrom = 'none'; allowedToCreateApps = $false; allowedToCreateSecurityGroups = $false; allowedToReadOtherUsers = $true
                permissionGrantPoliciesAssigned = @()
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureGuestInviteRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
    }

    It 'Reports NotApplicable when no AuthorizationPolicy entity exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureGuestInviteRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'COL-002-NO-POLICY-FOUND'
    }
}

Describe 'PAS-005: Test-EntraPostureAdminSelfServicePasswordResetControl' {
    It 'fails when allowedToUseSSPR is true and passes when false' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{ allowedToUseSSPR = $true }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAdminSelfServicePasswordResetControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'PAS-005-ADMIN-SSPR-ALLOWED'

        $dir2 = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir2 -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{ allowedToUseSSPR = $false }))
        )
        $provider2 = New-EntraPostureEvidenceProvider -SnapshotPath $dir2
        $result2 = Test-EntraPostureAdminSelfServicePasswordResetControl -EvidenceProvider $provider2
        $result2[0].Status | Should -Be 'Pass'
    }
}

Describe 'USR-002: Test-EntraPostureNonAdminTenantCreationControl' {
    It 'fails when allowedToCreateTenants is true and passes when false' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{ allowedToCreateTenants = $true }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureNonAdminTenantCreationControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'

        $dir2 = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir2 -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{ allowedToCreateTenants = $false }))
        )
        $provider2 = New-EntraPostureEvidenceProvider -SnapshotPath $dir2
        $result2 = Test-EntraPostureNonAdminTenantCreationControl -EvidenceProvider $provider2
        $result2[0].Status | Should -Be 'Pass'
    }
}

Describe 'USR-003: Test-EntraPostureBitlockerKeyReadAccessControl' {
    It 'fails when allowedToReadBitlockerKeysForOwnedDevice is true and passes when false' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{ allowedToReadBitlockerKeysForOwnedDevice = $true }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureBitlockerKeyReadAccessControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'

        $dir2 = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir2 -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{ allowedToReadBitlockerKeysForOwnedDevice = $false }))
        )
        $provider2 = New-EntraPostureEvidenceProvider -SnapshotPath $dir2
        $result2 = Test-EntraPostureBitlockerKeyReadAccessControl -EvidenceProvider $provider2
        $result2[0].Status | Should -Be 'Pass'
    }
}

Describe 'USR-004: Test-EntraPostureUserAppConsentControl' {
    It 'fails on the legacy policy, fails on a custom policy, passes on empty and on the recommended policy' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                permissionGrantPoliciesAssigned = @('managePermissionGrantsForSelf.microsoft-user-default-legacy')
            }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureUserAppConsentControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'USR-004-LEGACY-CONSENT-POLICY'

        $dirCustom = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirCustom -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                permissionGrantPoliciesAssigned = @('managePermissionGrantsForSelf.some-custom-policy')
            }))
        )
        $providerCustom = New-EntraPostureEvidenceProvider -SnapshotPath $dirCustom
        $resultCustom = Test-EntraPostureUserAppConsentControl -EvidenceProvider $providerCustom
        $resultCustom[0].Status | Should -Be 'Fail'
        $resultCustom[0].ReasonCode | Should -Be 'USR-004-CUSTOM-CONSENT-POLICY'

        $dirEmpty = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirEmpty -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{ permissionGrantPoliciesAssigned = @() }))
        )
        $providerEmpty = New-EntraPostureEvidenceProvider -SnapshotPath $dirEmpty
        $resultEmpty = Test-EntraPostureUserAppConsentControl -EvidenceProvider $providerEmpty
        $resultEmpty[0].Status | Should -Be 'Pass'
        $resultEmpty[0].ReasonCode | Should -Be 'USR-004-CONSENT-DISABLED'

        $dirRecommended = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirRecommended -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestEntity -EntityId 'default' -EntityType 'AuthorizationPolicy' -Properties ([ordered]@{
                permissionGrantPoliciesAssigned = @('managePermissionGrantsForSelf.microsoft-user-default-recommended')
            }))
        )
        $providerRecommended = New-EntraPostureEvidenceProvider -SnapshotPath $dirRecommended
        $resultRecommended = Test-EntraPostureUserAppConsentControl -EvidenceProvider $providerRecommended
        $resultRecommended[0].Status | Should -Be 'Pass'
        $resultRecommended[0].ReasonCode | Should -Be 'USR-004-RESTRICTED-CONSENT-POLICY'
    }
}
