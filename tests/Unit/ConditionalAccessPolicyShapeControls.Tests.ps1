#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2 (zero-new-evidence matrix-row slice, resumed 2026-08-08): CAP-001
    through CAP-010, the 10 "zero new evidence domain" Conditional Access policy-shape checks
    built from 15-feature-parity-matrix.md's canonical registry. CAP-011 excluded -- needs
    administrative-unit-scoped role assignment evidence this project doesn't capture (every
    DirectoryRoleAssignment relationship is hardcoded scope='directory').
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateDeviceCodeFlowRestriction.ps1',
        'src/Controls/EvaluateSecurityInfoRegistrationRestriction.ps1',
        'src/Controls/EvaluateLegacyAuthenticationBlock.ps1',
        'src/Controls/EvaluateDeviceRegistrationMfa.ps1',
        'src/Controls/EvaluatePhishingResistantMfaEnforcement.ps1',
        'src/Controls/EvaluateCombinedRiskPolicy.ps1',
        'src/Controls/EvaluateSignInRiskManagement.ps1',
        'src/Controls/EvaluateUserRiskManagement.ps1',
        'src/Controls/EvaluateBroadMfaEnforcement.ps1',
        'src/Controls/EvaluateTierZeroRoleCaCoverage.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "cap-controls-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestCaPolicy {
        param(
            [string]$Id, [string]$State = 'enabled',
            [string[]]$IncludeUsers = @(), [string[]]$IncludeRoles = @(),
            [string[]]$ClientAppTypes = @(), [string[]]$SignInRiskLevels = @(), [string[]]$UserRiskLevels = @(),
            [string[]]$IncludeUserActions = @(), [string]$AuthFlowTransferMethod = $null,
            [string[]]$BuiltInControls = @(), $AuthenticationStrengthId = $null
        )
        return [ordered]@{
            entityId = $Id; entityType = 'ConditionalAccessPolicy'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                state = $State; createdDateTime = $null; modifiedDateTime = $null
                conditions = [ordered]@{
                    clientAppTypes = $ClientAppTypes; signInRiskLevels = $SignInRiskLevels; userRiskLevels = $UserRiskLevels
                    users = [ordered]@{ includeUsers = $IncludeUsers; excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = $IncludeRoles; excludeRoles = @() }
                    applications = [ordered]@{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = $IncludeUserActions }
                    platforms = [ordered]@{ includePlatforms = @(); excludePlatforms = @() }
                    locations = [ordered]@{ includeLocations = @(); excludeLocations = @() }
                    devices = [ordered]@{ deviceFilterMode = $null; deviceFilterRule = $null }
                    authenticationFlowTransferMethods = $AuthFlowTransferMethod
                }
                grantControls = [ordered]@{ operator = 'OR'; builtInControls = $BuiltInControls; authenticationStrengthId = $AuthenticationStrengthId }
            }
        }
    }

    function script:New-TestAuthStrength {
        param([string]$Id, [string[]]$AllowedCombinations)
        return [ordered]@{
            entityId = $Id; entityType = 'AuthenticationStrengthPolicy'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ allowedCombinations = $AllowedCombinations; policyType = 'custom'; requirementsSatisfied = 'mfa' }
        }
    }

    function script:New-TestGaRoleEntity {
        return [ordered]@{
            entityId = 'ga-role'; entityType = 'DirectoryRole'; tenantScope = 't1'; displayName = 'Global Administrator'
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; properties = [ordered]@{}; redacted = $false
        }
    }

    function script:New-TestDirectoryRoleAssignmentRelationship {
        param([string]$PrincipalId, [string]$RoleId)
        return [ordered]@{
            relationshipId = "$PrincipalId::$RoleId::DirectoryRoleAssignment"; sourceEntityId = $PrincipalId; targetEntityId = $RoleId
            relationshipType = 'DirectoryRoleAssignment'; assignmentState = 'Active'; scope = 'directory'
            provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }
            validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false }
        }
    }
}

Describe 'CAP-001: Test-EntraPostureDeviceCodeFlowRestrictionControl' {
    It 'fails when no policy blocks device code flow' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureDeviceCodeFlowRestrictionControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
    }

    It 'passes when an enabled policy blocks device code flow' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -AuthFlowTransferMethod 'deviceCodeFlow' -BuiltInControls @('block'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureDeviceCodeFlowRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
    }

    It 'ignores a disabled policy' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -State 'disabled' -AuthFlowTransferMethod 'deviceCodeFlow' -BuiltInControls @('block'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureDeviceCodeFlowRestrictionControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
    }
}

Describe 'CAP-002: Test-EntraPostureSecurityInfoRegistrationRestrictionControl' {
    It 'passes when a policy governs security info registration' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -IncludeUserActions @('urn:user:registersecurityinfo') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureSecurityInfoRegistrationRestrictionControl -EvidenceProvider $provider)[0].Status | Should -Be 'Pass'
    }

    It 'fails when no policy targets the action' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureSecurityInfoRegistrationRestrictionControl -EvidenceProvider $provider)[0].Status | Should -Be 'Fail'
    }
}

Describe 'CAP-003: Test-EntraPostureLegacyAuthenticationBlockControl' {
    It 'passes when a policy blocks exchangeActiveSync' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -ClientAppTypes @('exchangeActiveSync') -BuiltInControls @('block'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureLegacyAuthenticationBlockControl -EvidenceProvider $provider)[0].Status | Should -Be 'Pass'
    }

    It 'fails when clientAppTypes is scoped but not blocked' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -ClientAppTypes @('exchangeActiveSync') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureLegacyAuthenticationBlockControl -EvidenceProvider $provider)[0].Status | Should -Be 'Fail'
    }
}

Describe 'CAP-004: Test-EntraPostureDeviceRegistrationMfaControl' {
    It 'passes when a policy requires MFA for device registration' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -IncludeUserActions @('urn:user:registerdevice') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureDeviceRegistrationMfaControl -EvidenceProvider $provider)[0].Status | Should -Be 'Pass'
    }

    It 'fails when no policy requires MFA for it' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureDeviceRegistrationMfaControl -EvidenceProvider $provider)[0].Status | Should -Be 'Fail'
    }
}

Describe 'CAP-005: Test-EntraPosturePhishingResistantMfaEnforcementControl' {
    It 'passes when a policy requires a phishing-resistant authentication strength' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -AuthenticationStrengthId 'strength-1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-strength-policies.jsonl' -Records @(
            (New-TestAuthStrength -Id 'strength-1' -AllowedCombinations @('fido2', 'windowsHelloForBusiness'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPosturePhishingResistantMfaEnforcementControl -EvidenceProvider $provider)[0].Status | Should -Be 'Pass'
    }

    It 'fails when the referenced strength allows a non-phishing-resistant method' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -AuthenticationStrengthId 'strength-1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-strength-policies.jsonl' -Records @(
            (New-TestAuthStrength -Id 'strength-1' -AllowedCombinations @('fido2', 'password'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPosturePhishingResistantMfaEnforcementControl -EvidenceProvider $provider)[0].Status | Should -Be 'Fail'
    }
}

Describe 'CAP-006: Test-EntraPostureCombinedRiskPolicyControl' {
    It 'passes only when one policy combines both risk dimensions' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -SignInRiskLevels @('high') -UserRiskLevels @('high') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureCombinedRiskPolicyControl -EvidenceProvider $provider)[0].Status | Should -Be 'Pass'
    }

    It 'fails when the two risk types are only covered by separate policies' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -SignInRiskLevels @('high') -BuiltInControls @('mfa')),
            (New-TestCaPolicy -Id 'p2' -UserRiskLevels @('high') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureCombinedRiskPolicyControl -EvidenceProvider $provider)[0].Status | Should -Be 'Fail'
    }
}

Describe 'CAP-007/CAP-008: risk-level management' {
    It 'CAP-007 passes when sign-in risk is managed' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -SignInRiskLevels @('high') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureSignInRiskManagementControl -EvidenceProvider $provider)[0].Status | Should -Be 'Pass'
    }

    It 'CAP-008 fails when no policy acts on user risk' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureUserRiskManagementControl -EvidenceProvider $provider)[0].Status | Should -Be 'Fail'
    }
}

Describe 'CAP-009: Test-EntraPostureBroadMfaEnforcementControl' {
    It 'passes when a policy requires MFA for All users' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -IncludeUsers @('All') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureBroadMfaEnforcementControl -EvidenceProvider $provider)[0].Status | Should -Be 'Pass'
    }

    It 'fails when MFA is only required for a scoped set of users' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -IncludeUsers @('user-1') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureBroadMfaEnforcementControl -EvidenceProvider $provider)[0].Status | Should -Be 'Fail'
    }
}

Describe 'CAP-010: Test-EntraPostureTierZeroRoleCaCoverageControl' {
    It 'reports NotApplicable when no Tier-0 role is active' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureTierZeroRoleCaCoverageControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
    }

    It 'fails an active Tier-0 role with no covering policy and passes one that is covered' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            (New-TestDirectoryRoleAssignmentRelationship -PrincipalId 'user-1' -RoleId 'ga-role')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureTierZeroRoleCaCoverageControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'

        $dir2 = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir2 -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $dir2 -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            (New-TestDirectoryRoleAssignmentRelationship -PrincipalId 'user-1' -RoleId 'ga-role')
        )
        Write-TestEvidenceFile -Dir $dir2 -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'p1' -IncludeRoles @('ga-role') -BuiltInControls @('mfa'))
        )
        $provider2 = New-EntraPostureEvidenceProvider -SnapshotPath $dir2
        $result2 = Test-EntraPostureTierZeroRoleCaCoverageControl -EvidenceProvider $provider2
        $result2[0].Status | Should -Be 'Pass'
    }
}
