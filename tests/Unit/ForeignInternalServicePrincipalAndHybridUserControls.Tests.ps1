#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2 (zero-new-evidence matrix-row slice, batch 4, 2026-08-08): ENT-006/
    007/011/012 (foreign/internal ServicePrincipal Entra/Azure role holding), APP-001 (app
    registration secrets), USR-007/008 (hybrid-synced users with Tier-0 roles), COL-001 (guest
    access level) -- all unlocked by batch 3's normalizer field extensions
    (ServicePrincipal.appOwnerOrganizationId, Application.passwordCredentialCount,
    User.onPremisesSyncEnabled, AuthorizationPolicy.guestUserRoleId).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateForeignServicePrincipalEntraRole.ps1',
        'src/Controls/EvaluateForeignServicePrincipalAzureRole.ps1',
        'src/Controls/EvaluateInternalServicePrincipalEntraRole.ps1',
        'src/Controls/EvaluateInternalServicePrincipalAzureRole.ps1',
        'src/Controls/EvaluateAppRegistrationSecrets.ps1',
        'src/Controls/EvaluateHybridUserEntraRole.ps1',
        'src/Controls/EvaluateHybridUserAzureRole.ps1',
        'src/Controls/EvaluateGuestAccessLevel.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "ent-usr-controls-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestServicePrincipalEntity {
        param([string]$Id, [string]$OwnerOrgId = $null)
        return [ordered]@{
            entityId = $Id; entityType = 'ServicePrincipal'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ appId = "app-$Id"; servicePrincipalType = 'Application'; accountEnabled = $true; appOwnerOrganizationId = $OwnerOrgId }
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

    function script:New-TestAzureRoleAssignmentEntity {
        param([string]$Id, [string]$PrincipalId)
        return [ordered]@{
            entityId = $Id; entityType = 'AzureRoleAssignment'; tenantScope = 't1'; displayName = $null
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ roleDefinitionId = 'rd1'; principalId = $PrincipalId; principalType = 'ServicePrincipal'; scope = '/subscriptions/sub-1'; createdOn = '2026-01-01T00:00:00Z' }
        }
    }

    function script:New-TestApplicationEntity {
        param([string]$Id, [int]$PasswordCredentialCount = 0)
        return [ordered]@{
            entityId = $Id; entityType = 'Application'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ appId = "app-$Id"; signInAudience = 'AzureADMyOrg'; createdDateTime = $null; passwordCredentialCount = $PasswordCredentialCount }
        }
    }

    function script:New-TestUserEntity {
        param([string]$Id, [bool]$OnPremisesSyncEnabled = $false)
        return [ordered]@{
            entityId = $Id; entityType = 'User'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ userPrincipalName = "$Id@t1"; accountEnabled = $true; userType = 'Member'; onPremisesSyncEnabled = $OnPremisesSyncEnabled }
        }
    }

    function script:New-TestAuthorizationPolicyEntity {
        param([string]$GuestUserRoleId)
        return [ordered]@{
            entityId = 'default'; entityType = 'AuthorizationPolicy'; tenantScope = 't1'; displayName = $null
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                allowInvitesFrom = 'everyone'; allowedToCreateApps = $false; allowedToCreateSecurityGroups = $false
                allowedToReadOtherUsers = $true; permissionGrantPoliciesAssigned = @(); guestUserRoleId = $GuestUserRoleId
            }
        }
    }
}

Describe 'ENT-006/ENT-011: foreign/internal service principal Entra role controls' {
    It 'ENT-006 fails a foreign service principal holding a Tier-0 role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principals.jsonl' -Records @(
            (New-TestServicePrincipalEntity -Id 'sp-1' -OwnerOrgId 'other-tenant')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            (New-TestDirectoryRoleAssignmentRelationship -PrincipalId 'sp-1' -RoleId 'ga-role')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureForeignServicePrincipalEntraRoleControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
    }

    It 'ENT-011 passes an internal service principal with no Tier-0 role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principals.jsonl' -Records @(
            (New-TestServicePrincipalEntity -Id 'sp-1' -OwnerOrgId 't1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureInternalServicePrincipalEntraRoleControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Pass'
    }
}

Describe 'ENT-007/ENT-012: foreign/internal service principal Azure role controls' {
    It 'ENT-007 fails a foreign service principal with an Azure role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principals.jsonl' -Records @(
            (New-TestServicePrincipalEntity -Id 'sp-1' -OwnerOrgId 'other-tenant')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/azure-role-assignments.jsonl' -Records @(
            (New-TestAzureRoleAssignmentEntity -Id 'ara-1' -PrincipalId 'sp-1')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureForeignServicePrincipalAzureRoleControl -EvidenceProvider $provider)[0].Status | Should -Be 'Fail'
    }

    It 'ENT-012 reports NotApplicable when no service principal exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureInternalServicePrincipalAzureRoleControl -EvidenceProvider $provider)[0].Status | Should -Be 'NotApplicable'
    }
}

Describe 'APP-001: Test-EntraPostureAppRegistrationSecretsControl' {
    It 'fails an application with a secret and passes one without' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-applications.jsonl' -Records @(
            (New-TestApplicationEntity -Id 'app-secret' -PasswordCredentialCount 1),
            (New-TestApplicationEntity -Id 'app-clean' -PasswordCredentialCount 0)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAppRegistrationSecretsControl -EvidenceProvider $provider
        ($result | Where-Object { $_.Scope -eq 'app-secret' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'app-clean' }).Status | Should -Be 'Pass'
    }
}

Describe 'USR-007/USR-008: hybrid user Entra/Azure role controls' {
    It 'USR-007 fails a hybrid-synced user holding a Tier-0 role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-users.jsonl' -Records @(
            (New-TestUserEntity -Id 'user-hybrid' -OnPremisesSyncEnabled $true)
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            (New-TestDirectoryRoleAssignmentRelationship -PrincipalId 'user-hybrid' -RoleId 'ga-role')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureHybridUserEntraRoleControl -EvidenceProvider $provider)[0].Status | Should -Be 'Fail'
    }

    It 'USR-008 reports NotApplicable when no user is hybrid-synced' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-users.jsonl' -Records @(
            (New-TestUserEntity -Id 'user-cloud' -OnPremisesSyncEnabled $false)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureHybridUserAzureRoleControl -EvidenceProvider $provider)[0].Status | Should -Be 'NotApplicable'
    }
}

Describe 'COL-001: Test-EntraPostureGuestAccessLevelControl' {
    It 'passes when guestUserRoleId is Restricted Guest User' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestAuthorizationPolicyEntity -GuestUserRoleId '2af84b1e-32c8-42b7-82bc-daa82404023b')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureGuestAccessLevelControl -EvidenceProvider $provider)[0].Status | Should -Be 'Pass'
    }

    It 'fails when guestUserRoleId is the default Guest User role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authorization-policy.jsonl' -Records @(
            (New-TestAuthorizationPolicyEntity -GuestUserRoleId '10dae51f-b6af-4016-8d66-8c2a99b929b3')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureGuestAccessLevelControl -EvidenceProvider $provider)[0].Status | Should -Be 'Fail'
    }
}
