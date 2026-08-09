#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2, the 109-row backlog completion pass (2026-08-08): PAS-001/002/003/
    004 (Password Rule Settings groupSetting), GRP-002/003/004 (Group.Unified groupSetting and
    Group entity fields), PIM-001 (existing PimEligible relationship, zero new evidence).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateBannedPasswordCheck.ps1',
        'src/Controls/EvaluateBannedPasswordListStrength.ps1',
        'src/Controls/EvaluateOnPremisesPasswordProtection.ps1',
        'src/Controls/EvaluateAccountLockoutSettings.ps1',
        'src/Controls/EvaluateM365GroupCreationRestriction.ps1',
        'src/Controls/EvaluatePublicM365Groups.ps1',
        'src/Controls/EvaluateDangerousDynamicGroupRule.ps1',
        'src/Controls/EvaluatePimEntraRoleAdoption.ps1',
        'src/Controls/EvaluateEntraLeastPrivilege.ps1',
        'src/Controls/TierZeroAzureRoleList.ps1',
        'src/Controls/EvaluateAzureLeastPrivilege.ps1',
        'src/Controls/EvaluateWeakProtectionEntraRole.ps1',
        'src/Controls/EvaluateWeakProtectionAzureRole.ps1',
        'src/Controls/EvaluateCaPolicyScopedRoleAssignment.ps1',
        'src/Common/ParseRogueAppsToml.ps1', 'src/Normalization/NormalizeKnownAbusedApp.ps1',
        'src/Controls/EvaluateKnownAbusedApp.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "backlog-completion-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestPasswordRuleSettingsEntity {
        param(
            [object]$EnableBannedPasswordCheck = $null,
            [object]$BannedPasswordListEntryCount = $null,
            [object]$EnableBannedPasswordCheckOnPremises = $null,
            [string]$BannedPasswordCheckOnPremisesMode = $null,
            [object]$LockoutDurationInSeconds = $null,
            [object]$LockoutThreshold = $null
        )
        return [ordered]@{
            entityId = 'pw-settings-1'; entityType = 'GroupSetting'; tenantScope = 't1'; displayName = 'Password Rule Settings'
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                templateId = '5cf42378-d67d-4f36-ba46-e8b86229381d'
                allowGuestsToBeGroupOwner = $null
                enableGroupCreation = $null
                enableBannedPasswordCheck = $EnableBannedPasswordCheck
                bannedPasswordListEntryCount = $BannedPasswordListEntryCount
                enableBannedPasswordCheckOnPremises = $EnableBannedPasswordCheckOnPremises
                bannedPasswordCheckOnPremisesMode = $BannedPasswordCheckOnPremisesMode
                lockoutDurationInSeconds = $LockoutDurationInSeconds
                lockoutThreshold = $LockoutThreshold
            }
        }
    }

    function script:New-TestUnifiedGroupSettingEntity {
        param([object]$EnableGroupCreation = $null)
        return [ordered]@{
            entityId = 'unified-1'; entityType = 'GroupSetting'; tenantScope = 't1'; displayName = 'Group.Unified'
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                templateId = '62375ab9-6b52-47ed-826b-58e47e0e304b'
                allowGuestsToBeGroupOwner = $null
                enableGroupCreation = $EnableGroupCreation
            }
        }
    }

    function script:New-TestGroupEntity {
        param([string]$Id, [string[]]$GroupTypes = @(), [string]$Visibility = $null, [string]$MembershipRule = $null)
        return [ordered]@{
            entityId = $Id; entityType = 'Group'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                groupTypes = $GroupTypes; securityEnabled = $false; mailEnabled = $true; isAssignableToRole = $false
                visibility = $Visibility; membershipRule = $MembershipRule
            }
        }
    }

    function script:New-TestAuthorizationPolicyEntity {
        param([string]$AllowInvitesFrom = 'none')
        return [ordered]@{
            entityId = 'default'; entityType = 'AuthorizationPolicy'; tenantScope = 't1'; displayName = $null
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ allowInvitesFrom = $AllowInvitesFrom }
        }
    }

    function script:New-TestPimEligibleRelationship {
        param([string]$PrincipalId, [string]$RoleId)
        return [ordered]@{
            relationshipId = "$PrincipalId::$RoleId::PimEligible"; sourceEntityId = $PrincipalId; targetEntityId = $RoleId
            relationshipType = 'PimEligible'; assignmentState = 'Eligible'; scope = 'directory'
            provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }
            validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false }
        }
    }

    function script:New-TestAzureRoleAssignmentEntity {
        param([string]$Id, [string]$RoleDefinitionId, [string]$PrincipalId, [string]$PrincipalType)
        return [ordered]@{
            entityId = $Id; entityType = 'AzureRoleAssignment'; tenantScope = 't1'; displayName = $null
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                roleDefinitionId = $RoleDefinitionId; principalId = $PrincipalId; principalType = $PrincipalType
                scope = '/subscriptions/sub1'; createdOn = '2026-01-01T00:00:00Z'
            }
        }
    }

    function script:New-TestCaPolicyWithRoles {
        param([string]$Id, [string]$State = 'enabled', [string[]]$IncludeRoles = @())
        return [ordered]@{
            entityId = $Id; entityType = 'ConditionalAccessPolicy'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                state = $State; createdDateTime = $null; modifiedDateTime = $null
                conditions = [ordered]@{
                    clientAppTypes = @(); signInRiskLevels = @(); userRiskLevels = @()
                    users = [ordered]@{ includeUsers = @(); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = $IncludeRoles; excludeRoles = @() }
                    applications = [ordered]@{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @() }
                    platforms = [ordered]@{ includePlatforms = @(); excludePlatforms = @() }
                    locations = [ordered]@{ includeLocations = @(); excludeLocations = @() }
                    devices = [ordered]@{ deviceFilterMode = $null; deviceFilterRule = $null }
                    authenticationFlowTransferMethods = $null
                }
                grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('mfa'); authenticationStrengthId = $null }
            }
        }
    }

    function script:New-TestRoleAssignmentScopeRelationship {
        param([string]$PrincipalId, [string]$RoleId, [string]$Scope = 'directory')
        return [ordered]@{
            relationshipId = "$PrincipalId::$RoleId::RoleAssignmentScope::assignment-$PrincipalId-$RoleId"
            sourceEntityId = $PrincipalId; targetEntityId = $RoleId
            relationshipType = 'RoleAssignmentScope'; assignmentState = 'Active'; scope = $Scope
            provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }
            validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false }
        }
    }

    function script:New-TestServicePrincipalEntity {
        param([string]$Id, [string]$AppId, [string]$DisplayName = $null)
        return [ordered]@{
            entityId = $Id; entityType = 'ServicePrincipal'; tenantScope = 't1'; displayName = $(if ($DisplayName) { $DisplayName } else { $Id })
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ appId = $AppId }
        }
    }

    function script:New-TestKnownAbusedAppEntity {
        param([string]$AppId, [string]$DisplayName, [string]$Description = 'test description')
        return [ordered]@{
            entityId = $AppId; entityType = 'KnownAbusedApp'; tenantScope = 't1'; displayName = $DisplayName
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                appOwnerOrganizationId = 'org-1'; appPublisherName = 'Publisher'; appPublisherId = 'pub-1'
                description = $Description; tags = @('BEC'); references = @(); dateAdded = '2024-01-01'
            }
        }
    }

    function script:New-TestKnownAbusedAppListMetadataEntity {
        param([string]$FilePath = '/path/to/known-abused-apps.toml', [string]$CommitDateUtc = $null, [string]$FetchedAtUtc = $null, [int]$AppCount = 1)
        return [ordered]@{
            entityId = 'default'; entityType = 'KnownAbusedAppListMetadata'; tenantScope = 't1'; displayName = $null
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ filePath = $FilePath; commitDateUtc = $CommitDateUtc; fetchedAtUtc = $FetchedAtUtc; appCount = $AppCount }
        }
    }

    function script:New-TestUserRegistrationDetailsEntity {
        param([string]$Id, [object]$IsMfaRegistered = $null, [object]$IsPasswordlessCapable = $null)
        return [ordered]@{
            entityId = $Id; entityType = 'UserRegistrationDetails'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                isAdmin = $null; isMfaRegistered = $IsMfaRegistered; isMfaCapable = $null
                isPasswordlessCapable = $IsPasswordlessCapable
                isSsprRegistered = $null; isSsprEnabled = $null; isSsprCapable = $null
                methodsRegistered = @(); userType = 'member'
            }
        }
    }
}

Describe 'PAS-001: Test-EntraPostureBannedPasswordCheckControl' {
    It 'fails when explicitly disabled, passes when enabled or absent' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-settings.jsonl' -Records @((New-TestPasswordRuleSettingsEntity -EnableBannedPasswordCheck $false))
        $result = Test-EntraPostureBannedPasswordCheckControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        $result[0].Status | Should -Be 'Fail'

        $dir2 = New-TestSnapshotDir
        $result2 = Test-EntraPostureBannedPasswordCheckControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir2)
        $result2[0].Status | Should -Be 'Pass'
    }
}

Describe 'PAS-002: Test-EntraPostureBannedPasswordListStrengthControl' {
    It 'is NotApplicable when disabled, fails under 10 entries, passes at 10+' {
        $dirDisabled = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirDisabled -RelativePath 'evidence/entra-group-settings.jsonl' -Records @((New-TestPasswordRuleSettingsEntity -EnableBannedPasswordCheck $false))
        (Test-EntraPostureBannedPasswordListStrengthControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirDisabled))[0].Status | Should -Be 'NotApplicable'

        $dirShort = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirShort -RelativePath 'evidence/entra-group-settings.jsonl' -Records @((New-TestPasswordRuleSettingsEntity -EnableBannedPasswordCheck $true -BannedPasswordListEntryCount 3))
        (Test-EntraPostureBannedPasswordListStrengthControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirShort))[0].Status | Should -Be 'Fail'

        $dirLong = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirLong -RelativePath 'evidence/entra-group-settings.jsonl' -Records @((New-TestPasswordRuleSettingsEntity -EnableBannedPasswordCheck $true -BannedPasswordListEntryCount 15))
        (Test-EntraPostureBannedPasswordListStrengthControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirLong))[0].Status | Should -Be 'Pass'
    }
}

Describe 'PAS-003: Test-EntraPostureOnPremisesPasswordProtectionControl' {
    It 'passes only when enabled and mode is Enforce' {
        $dirEnforced = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirEnforced -RelativePath 'evidence/entra-group-settings.jsonl' -Records @(
            (New-TestPasswordRuleSettingsEntity -EnableBannedPasswordCheck $true -EnableBannedPasswordCheckOnPremises $true -BannedPasswordCheckOnPremisesMode 'Enforce')
        )
        (Test-EntraPostureOnPremisesPasswordProtectionControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirEnforced))[0].Status | Should -Be 'Pass'

        $dirAudit = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirAudit -RelativePath 'evidence/entra-group-settings.jsonl' -Records @(
            (New-TestPasswordRuleSettingsEntity -EnableBannedPasswordCheck $true -EnableBannedPasswordCheckOnPremises $true -BannedPasswordCheckOnPremisesMode 'Audit')
        )
        (Test-EntraPostureOnPremisesPasswordProtectionControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirAudit))[0].Status | Should -Be 'Fail'
    }
}

Describe 'PAS-004: Test-EntraPostureAccountLockoutSettingsControl' {
    It 'passes on defaults or stricter, fails when weaker' {
        $dirNone = New-TestSnapshotDir
        $result = Test-EntraPostureAccountLockoutSettingsControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirNone)
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'PAS-004-DEFAULT-LOCKOUT-SETTINGS'

        $dirWeak = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirWeak -RelativePath 'evidence/entra-group-settings.jsonl' -Records @(
            (New-TestPasswordRuleSettingsEntity -LockoutThreshold 20 -LockoutDurationInSeconds 30)
        )
        (Test-EntraPostureAccountLockoutSettingsControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirWeak))[0].Status | Should -Be 'Fail'

        $dirStrict = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirStrict -RelativePath 'evidence/entra-group-settings.jsonl' -Records @(
            (New-TestPasswordRuleSettingsEntity -LockoutThreshold 5 -LockoutDurationInSeconds 120)
        )
        (Test-EntraPostureAccountLockoutSettingsControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirStrict))[0].Status | Should -Be 'Pass'
    }
}

Describe 'GRP-002: Test-EntraPostureM365GroupCreationRestrictionControl' {
    It 'fails when unrestricted or absent, passes when restricted' {
        $dirAbsent = New-TestSnapshotDir
        (Test-EntraPostureM365GroupCreationRestrictionControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirAbsent))[0].Status | Should -Be 'Fail'

        $dirRestricted = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirRestricted -RelativePath 'evidence/entra-group-settings.jsonl' -Records @((New-TestUnifiedGroupSettingEntity -EnableGroupCreation $false))
        (Test-EntraPostureM365GroupCreationRestrictionControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirRestricted))[0].Status | Should -Be 'Pass'
    }
}

Describe 'GRP-003: Test-EntraPosturePublicM365GroupsControl' {
    It 'fails a static public M365 group, passes a dynamic public one and a private one' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @(
            (New-TestGroupEntity -Id 'grp-public-static' -GroupTypes @('Unified') -Visibility 'Public'),
            (New-TestGroupEntity -Id 'grp-public-dynamic' -GroupTypes @('Unified', 'DynamicMembership') -Visibility 'Public'),
            (New-TestGroupEntity -Id 'grp-private' -GroupTypes @('Unified') -Visibility 'Private')
        )
        $result = Test-EntraPosturePublicM365GroupsControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        ($result | Where-Object { $_.Scope -eq 'grp-public-static' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'grp-public-dynamic' }).Status | Should -Be 'Pass'
        ($result | Where-Object { $_.Scope -eq 'grp-private' }).Status | Should -Be 'Pass'
    }
}

Describe 'GRP-004: Test-EntraPostureDangerousDynamicGroupRuleControl' {
    It 'fails on an always-risky attribute unconditionally, and on an invite-dependent attribute only when invites are possible' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @(
            (New-TestGroupEntity -Id 'grp-risky' -GroupTypes @('DynamicMembership') -MembershipRule '(user.mobilePhone -eq "555")'),
            (New-TestGroupEntity -Id 'grp-safe' -GroupTypes @('DynamicMembership') -MembershipRule '(user.department -eq "Finance")'),
            (New-TestGroupEntity -Id 'grp-invite-linked' -GroupTypes @('DynamicMembership') -MembershipRule '(user.mail -contains "@partner.com")')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @((New-TestAuthorizationPolicyEntity -AllowInvitesFrom 'none'))
        $result = Test-EntraPostureDangerousDynamicGroupRuleControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        ($result | Where-Object { $_.Scope -eq 'grp-risky' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'grp-safe' }).Status | Should -Be 'Pass'
        ($result | Where-Object { $_.Scope -eq 'grp-invite-linked' }).Status | Should -Be 'Pass'

        $dirInvites = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirInvites -RelativePath 'evidence/entra-groups.jsonl' -Records @(
            (New-TestGroupEntity -Id 'grp-invite-linked' -GroupTypes @('DynamicMembership') -MembershipRule '(user.mail -contains "@partner.com")')
        )
        Write-TestEvidenceFile -Dir $dirInvites -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @((New-TestAuthorizationPolicyEntity -AllowInvitesFrom 'everyone'))
        $resultInvites = Test-EntraPostureDangerousDynamicGroupRuleControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirInvites)
        $resultInvites[0].Status | Should -Be 'Fail'
    }
}

Describe 'PIM-001: Test-EntraPosturePimEntraRoleAdoptionControl' {
    It 'fails with zero PIM-eligible assignments, passes with at least one' {
        $dirNone = New-TestSnapshotDir
        (Test-EntraPosturePimEntraRoleAdoptionControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirNone))[0].Status | Should -Be 'Fail'

        $dirSome = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirSome -RelativePath 'evidence/entra-pim-eligibility.jsonl' -Records @((New-TestPimEligibleRelationship -PrincipalId 'user-1' -RoleId 'ga-role'))
        (Test-EntraPosturePimEntraRoleAdoptionControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirSome))[0].Status | Should -Be 'Pass'
    }
}

Describe 'USR-006: Test-EntraPostureEntraLeastPrivilegeControl' {
    It 'counts direct and group-transitive Tier-0 role holders, deduplicated, against the 5-user threshold' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @(
            [ordered]@{ entityId = 'ga-role'; entityType = 'DirectoryRole'; tenantScope = 't1'; displayName = 'Global Administrator'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; properties = [ordered]@{}; redacted = $false }
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-users.jsonl' -Records @(
            [ordered]@{ entityId = 'u1'; entityType = 'User'; tenantScope = 't1'; displayName = 'u1'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } },
            [ordered]@{ entityId = 'u2'; entityType = 'User'; tenantScope = 't1'; displayName = 'u2'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } },
            [ordered]@{ entityId = 'u3'; entityType = 'User'; tenantScope = 't1'; displayName = 'u3'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } },
            [ordered]@{ entityId = 'u4'; entityType = 'User'; tenantScope = 't1'; displayName = 'u4'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } },
            [ordered]@{ entityId = 'u5'; entityType = 'User'; tenantScope = 't1'; displayName = 'u5'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } },
            [ordered]@{ entityId = 'u-disabled'; entityType = 'User'; tenantScope = 't1'; displayName = 'u-disabled'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $false } }
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            [ordered]@{ relationshipId = 'u1::ga-role::DirectoryRoleAssignment'; sourceEntityId = 'u1'; targetEntityId = 'ga-role'; relationshipType = 'DirectoryRoleAssignment'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false } },
            [ordered]@{ relationshipId = 'u2::ga-role::DirectoryRoleAssignment'; sourceEntityId = 'u2'; targetEntityId = 'ga-role'; relationshipType = 'DirectoryRoleAssignment'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false } },
            [ordered]@{ relationshipId = 'grp1::ga-role::DirectoryRoleAssignment'; sourceEntityId = 'grp1'; targetEntityId = 'ga-role'; relationshipType = 'DirectoryRoleAssignment'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false } },
            [ordered]@{ relationshipId = 'u-disabled::ga-role::DirectoryRoleAssignment'; sourceEntityId = 'u-disabled'; targetEntityId = 'ga-role'; relationshipType = 'DirectoryRoleAssignment'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false } }
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-memberships.jsonl' -Records @(
            [ordered]@{ relationshipId = 'u3::grp1::TransitiveMemberOf'; sourceEntityId = 'u3'; targetEntityId = 'grp1'; relationshipType = 'TransitiveMemberOf'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $true } },
            [ordered]@{ relationshipId = 'u4::grp1::TransitiveMemberOf'; sourceEntityId = 'u4'; targetEntityId = 'grp1'; relationshipType = 'TransitiveMemberOf'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $true } },
            [ordered]@{ relationshipId = 'u5::grp1::TransitiveMemberOf'; sourceEntityId = 'u5'; targetEntityId = 'grp1'; relationshipType = 'TransitiveMemberOf'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $true } }
        )
        $result = Test-EntraPostureEntraLeastPrivilegeControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'USR-006-EXCESSIVE-TIER-ZERO-USERS'
        $result[0].Rationale | Should -Match '5 enabled users'
    }

    It 'passes when below the threshold' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @(
            [ordered]@{ entityId = 'ga-role'; entityType = 'DirectoryRole'; tenantScope = 't1'; displayName = 'Global Administrator'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; properties = [ordered]@{}; redacted = $false }
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-users.jsonl' -Records @(
            [ordered]@{ entityId = 'u1'; entityType = 'User'; tenantScope = 't1'; displayName = 'u1'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } }
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            [ordered]@{ relationshipId = 'u1::ga-role::DirectoryRoleAssignment'; sourceEntityId = 'u1'; targetEntityId = 'ga-role'; relationshipType = 'DirectoryRoleAssignment'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false } }
        )
        $result = Test-EntraPostureEntraLeastPrivilegeControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        $result[0].Status | Should -Be 'Pass'
    }
}

Describe 'USR-009: Test-EntraPostureAzureLeastPrivilegeControl' {
    It 'counts direct and group-transitive Tier-0 Azure role holders, deduplicated, against the 8-user threshold, excluding non-Tier-0 roles, disabled users, and non-user principals' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-users.jsonl' -Records @(
            1..8 | ForEach-Object {
                [ordered]@{ entityId = "u$_"; entityType = 'User'; tenantScope = 't1'; displayName = "u$_"; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } }
            }
            [ordered]@{ entityId = 'u-disabled'; entityType = 'User'; tenantScope = 't1'; displayName = 'u-disabled'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $false } }
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/azure-role-assignments.jsonl' -Records @(
            (New-TestAzureRoleAssignmentEntity -Id 'ra1' -RoleDefinitionId '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -PrincipalId 'u1' -PrincipalType 'User'),
            (New-TestAzureRoleAssignmentEntity -Id 'ra2' -RoleDefinitionId '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' -PrincipalId 'u2' -PrincipalType 'User'),
            (New-TestAzureRoleAssignmentEntity -Id 'ra3' -RoleDefinitionId '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/f58310d9-a9f6-439a-9e8d-f62e7b41a168' -PrincipalId 'u3' -PrincipalType 'User'),
            (New-TestAzureRoleAssignmentEntity -Id 'ra4' -RoleDefinitionId '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -PrincipalId 'u4' -PrincipalType 'User'),
            (New-TestAzureRoleAssignmentEntity -Id 'ra5' -RoleDefinitionId '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -PrincipalId 'u5' -PrincipalType 'User'),
            (New-TestAzureRoleAssignmentEntity -Id 'ra6' -RoleDefinitionId '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -PrincipalId 'grp1' -PrincipalType 'Group'),
            (New-TestAzureRoleAssignmentEntity -Id 'ra-contributor' -RoleDefinitionId '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c' -PrincipalId 'u-disabled' -PrincipalType 'User'),
            (New-TestAzureRoleAssignmentEntity -Id 'ra-disabled-owner' -RoleDefinitionId '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -PrincipalId 'u-disabled' -PrincipalType 'User')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-memberships.jsonl' -Records @(
            [ordered]@{ relationshipId = 'u6::grp1::TransitiveMemberOf'; sourceEntityId = 'u6'; targetEntityId = 'grp1'; relationshipType = 'TransitiveMemberOf'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $true } },
            [ordered]@{ relationshipId = 'u7::grp1::TransitiveMemberOf'; sourceEntityId = 'u7'; targetEntityId = 'grp1'; relationshipType = 'TransitiveMemberOf'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $true } },
            [ordered]@{ relationshipId = 'u8::grp1::TransitiveMemberOf'; sourceEntityId = 'u8'; targetEntityId = 'grp1'; relationshipType = 'TransitiveMemberOf'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $true } }
        )
        $result = Test-EntraPostureAzureLeastPrivilegeControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'USR-009-EXCESSIVE-TIER-ZERO-USERS'
        $result[0].Rationale | Should -Match '8 enabled users'
    }

    It 'passes when below the threshold and when no Azure RBAC evidence was collected' {
        $dirNone = New-TestSnapshotDir
        $resultNone = Test-EntraPostureAzureLeastPrivilegeControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirNone)
        $resultNone[0].Status | Should -Be 'Pass'
        $resultNone[0].ReasonCode | Should -Be 'USR-009-TIER-ZERO-USERS-WITHIN-RANGE'

        $dirFew = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dirFew -RelativePath 'evidence/entra-users.jsonl' -Records @(
            [ordered]@{ entityId = 'u1'; entityType = 'User'; tenantScope = 't1'; displayName = 'u1'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } }
        )
        Write-TestEvidenceFile -Dir $dirFew -RelativePath 'evidence/azure-role-assignments.jsonl' -Records @(
            (New-TestAzureRoleAssignmentEntity -Id 'ra1' -RoleDefinitionId '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -PrincipalId 'u1' -PrincipalType 'User')
        )
        $resultFew = Test-EntraPostureAzureLeastPrivilegeControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dirFew)
        $resultFew[0].Status | Should -Be 'Pass'
    }
}

Describe 'USR-010: Test-EntraPostureWeakProtectionEntraRoleControl' {
    It 'evaluates each direct and group-transitive Tier-0 Entra role holder against isPasswordlessCapable, failing on missing registration evidence too' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @(
            [ordered]@{ entityId = 'ga-role'; entityType = 'DirectoryRole'; tenantScope = 't1'; displayName = 'Global Administrator'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; properties = [ordered]@{}; redacted = $false }
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-users.jsonl' -Records @(
            [ordered]@{ entityId = 'u1'; entityType = 'User'; tenantScope = 't1'; displayName = 'u1'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } },
            [ordered]@{ entityId = 'u2'; entityType = 'User'; tenantScope = 't1'; displayName = 'u2'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } },
            [ordered]@{ entityId = 'u3'; entityType = 'User'; tenantScope = 't1'; displayName = 'u3'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } }
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            [ordered]@{ relationshipId = 'u1::ga-role::DirectoryRoleAssignment'; sourceEntityId = 'u1'; targetEntityId = 'ga-role'; relationshipType = 'DirectoryRoleAssignment'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false } },
            [ordered]@{ relationshipId = 'u2::ga-role::DirectoryRoleAssignment'; sourceEntityId = 'u2'; targetEntityId = 'ga-role'; relationshipType = 'DirectoryRoleAssignment'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false } },
            [ordered]@{ relationshipId = 'grp1::ga-role::DirectoryRoleAssignment'; sourceEntityId = 'grp1'; targetEntityId = 'ga-role'; relationshipType = 'DirectoryRoleAssignment'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false } }
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-memberships.jsonl' -Records @(
            [ordered]@{ relationshipId = 'u3::grp1::TransitiveMemberOf'; sourceEntityId = 'u3'; targetEntityId = 'grp1'; relationshipType = 'TransitiveMemberOf'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $true } }
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-user-registration-details.jsonl' -Records @(
            (New-TestUserRegistrationDetailsEntity -Id 'u1' -IsMfaRegistered $true -IsPasswordlessCapable $true),
            (New-TestUserRegistrationDetailsEntity -Id 'u2' -IsMfaRegistered $true -IsPasswordlessCapable $false)
        )
        $result = Test-EntraPostureWeakProtectionEntraRoleControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        ($result | Where-Object { $_.Scope -eq 'u1' }).Status | Should -Be 'Pass'
        ($result | Where-Object { $_.Scope -eq 'u1' }).ReasonCode | Should -Be 'USR-010-PASSWORDLESS-CAPABLE'
        ($result | Where-Object { $_.Scope -eq 'u2' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'u2' }).ReasonCode | Should -Be 'USR-010-NOT-PASSWORDLESS-CAPABLE'
        ($result | Where-Object { $_.Scope -eq 'u3' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'u3' }).ReasonCode | Should -Be 'USR-010-NO-REGISTRATION-EVIDENCE'
    }

    It 'is NotApplicable when no enabled user holds a curated Tier-0 Entra ID role' {
        $dir = New-TestSnapshotDir
        $result = Test-EntraPostureWeakProtectionEntraRoleControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'USR-010-NO-TIER-ZERO-USERS'
    }
}

Describe 'USR-011: Test-EntraPostureWeakProtectionAzureRoleControl' {
    It 'evaluates each direct and group-transitive Tier-0 Azure role holder against isPasswordlessCapable, failing on missing registration evidence too' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-users.jsonl' -Records @(
            [ordered]@{ entityId = 'u1'; entityType = 'User'; tenantScope = 't1'; displayName = 'u1'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } },
            [ordered]@{ entityId = 'u2'; entityType = 'User'; tenantScope = 't1'; displayName = 'u2'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } },
            [ordered]@{ entityId = 'u3'; entityType = 'User'; tenantScope = 't1'; displayName = 'u3'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false; properties = [ordered]@{ accountEnabled = $true } }
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/azure-role-assignments.jsonl' -Records @(
            (New-TestAzureRoleAssignmentEntity -Id 'ra1' -RoleDefinitionId '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -PrincipalId 'u1' -PrincipalType 'User'),
            (New-TestAzureRoleAssignmentEntity -Id 'ra2' -RoleDefinitionId '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635' -PrincipalId 'u2' -PrincipalType 'User'),
            (New-TestAzureRoleAssignmentEntity -Id 'ra3' -RoleDefinitionId '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' -PrincipalId 'grp1' -PrincipalType 'Group')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-memberships.jsonl' -Records @(
            [ordered]@{ relationshipId = 'u3::grp1::TransitiveMemberOf'; sourceEntityId = 'u3'; targetEntityId = 'grp1'; relationshipType = 'TransitiveMemberOf'; assignmentState = 'Active'; scope = 'directory'; provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }; validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $true } }
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-user-registration-details.jsonl' -Records @(
            (New-TestUserRegistrationDetailsEntity -Id 'u1' -IsMfaRegistered $true -IsPasswordlessCapable $true),
            (New-TestUserRegistrationDetailsEntity -Id 'u2' -IsMfaRegistered $true -IsPasswordlessCapable $false)
        )
        $result = Test-EntraPostureWeakProtectionAzureRoleControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        ($result | Where-Object { $_.Scope -eq 'u1' }).Status | Should -Be 'Pass'
        ($result | Where-Object { $_.Scope -eq 'u1' }).ReasonCode | Should -Be 'USR-011-PASSWORDLESS-CAPABLE'
        ($result | Where-Object { $_.Scope -eq 'u2' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'u2' }).ReasonCode | Should -Be 'USR-011-NOT-PASSWORDLESS-CAPABLE'
        ($result | Where-Object { $_.Scope -eq 'u3' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'u3' }).ReasonCode | Should -Be 'USR-011-NO-REGISTRATION-EVIDENCE'
    }

    It 'is NotApplicable when no enabled user holds a curated Tier-0 Azure RBAC role' {
        $dir = New-TestSnapshotDir
        $result = Test-EntraPostureWeakProtectionAzureRoleControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'USR-011-NO-TIER-ZERO-USERS'
    }
}

Describe 'CAP-011: Test-EntraPostureCaPolicyScopedRoleAssignmentControl' {
    It 'fails a role-scoped policy when an included role has an AU-scoped assignment, passes when all assignments are directory-wide, and ignores disabled policies and roles with no assignments at all' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicyWithRoles -Id 'p-gapped' -IncludeRoles @('ga-role')),
            (New-TestCaPolicyWithRoles -Id 'p-clean' -IncludeRoles @('pra-role')),
            (New-TestCaPolicyWithRoles -Id 'p-no-assignments' -IncludeRoles @('unused-role')),
            (New-TestCaPolicyWithRoles -Id 'p-disabled' -State 'disabled' -IncludeRoles @('ga-role'))
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignment-scopes.jsonl' -Records @(
            (New-TestRoleAssignmentScopeRelationship -PrincipalId 'u1' -RoleId 'ga-role' -Scope 'directory'),
            (New-TestRoleAssignmentScopeRelationship -PrincipalId 'u2' -RoleId 'ga-role' -Scope 'administrativeUnit'),
            (New-TestRoleAssignmentScopeRelationship -PrincipalId 'u3' -RoleId 'pra-role' -Scope 'directory')
        )
        $result = Test-EntraPostureCaPolicyScopedRoleAssignmentControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        ($result | Where-Object { $_.Scope -eq 'p-gapped' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'p-gapped' }).ReasonCode | Should -Be 'CAP-011-SCOPED-ASSIGNMENT-GAP'
        ($result | Where-Object { $_.Scope -eq 'p-clean' }).Status | Should -Be 'Pass'
        ($result | Where-Object { $_.Scope -eq 'p-clean' }).ReasonCode | Should -Be 'CAP-011-NO-SCOPED-ASSIGNMENT-GAP'
        ($result | Where-Object { $_.Scope -eq 'p-no-assignments' }).Status | Should -Be 'Pass'
        ($result | Where-Object { $_.Scope -eq 'p-disabled' }) | Should -BeNullOrEmpty
    }

    It 'is NotApplicable when no enabled policy names any role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicyWithRoles -Id 'p1' -IncludeRoles @())
        )
        $result = Test-EntraPostureCaPolicyScopedRoleAssignmentControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'CAP-011-NO-ROLE-SCOPED-POLICIES'
    }
}

Describe 'ENT-013: Test-EntraPostureKnownAbusedAppControl' {
    It 'fails a service principal whose appId matches a known-abused-app entry, passes one that does not' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principals.jsonl' -Records @(
            (New-TestServicePrincipalEntity -Id 'sp-bad' -AppId 'app-bad' -DisplayName 'Bad App'),
            (New-TestServicePrincipalEntity -Id 'sp-good' -AppId 'app-good' -DisplayName 'Good App')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/known-abused-apps.jsonl' -Records @(
            (New-TestKnownAbusedAppEntity -AppId 'app-bad' -DisplayName 'Known Bad App' -Description 'Exfiltrates mailboxes.')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/known-abused-app-list-metadata.jsonl' -Records @(
            (New-TestKnownAbusedAppListMetadataEntity -CommitDateUtc '2026-04-07T14:45:48Z' -AppCount 1)
        )
        $result = Test-EntraPostureKnownAbusedAppControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        $badResult = $result | Where-Object { $_.Scope -eq 'sp-bad' }
        $badResult.Status | Should -Be 'Fail'
        $badResult.ReasonCode | Should -Be 'ENT-013-KNOWN-ABUSED-APP-MATCH'
        $badResult.Rationale | Should -Match 'Known Bad App'
        $badResult.Rationale | Should -Match 'does not confirm malicious intent'
        $badResult.Rationale | Should -Match '2026-04-07T14:45:48Z'

        $goodResult = $result | Where-Object { $_.Scope -eq 'sp-good' }
        $goodResult.Status | Should -Be 'Pass'
        $goodResult.ReasonCode | Should -Be 'ENT-013-NO-KNOWN-ABUSED-APP-MATCH'
    }

    It 'is NotApplicable when no ServicePrincipal entity exists' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/known-abused-apps.jsonl' -Records @(
            (New-TestKnownAbusedAppEntity -AppId 'app-bad' -DisplayName 'Known Bad App')
        )
        $result = Test-EntraPostureKnownAbusedAppControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'ENT-013-NO-SERVICE-PRINCIPALS'
    }

    It 'is NotApplicable (not a vacuous Pass) when no known-abused-app reference data was ever configured' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principals.jsonl' -Records @(
            (New-TestServicePrincipalEntity -Id 'sp-1' -AppId 'app-1')
        )
        $result = Test-EntraPostureKnownAbusedAppControl -EvidenceProvider (New-EntraPostureEvidenceProvider -SnapshotPath $dir)
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'ENT-013-NO-REFERENCE-DATA'
    }
}
