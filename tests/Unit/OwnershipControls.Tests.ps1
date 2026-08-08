#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2, new-evidence phase (batch 6, 2026-08-08): ENT-003/APP-003
    (non-Tier-0 owner, ServicePrincipal and Application respectively) and ENT-008 (foreign
    service principal owning objects) -- all unlocked by CollectApplications.ps1's and
    CollectServicePrincipals.ps1's new owners/ownedObjects N+1 fetches.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateEnterpriseAppOwnerTier.ps1',
        'src/Controls/EvaluateAppRegistrationOwnerTier.ps1',
        'src/Controls/EvaluateForeignServicePrincipalOwnedObjects.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "ownership-controls-test-$([guid]::NewGuid())"
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

    function script:New-TestApplicationEntity {
        param([string]$Id)
        return [ordered]@{
            entityId = $Id; entityType = 'Application'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ appId = "app-$Id"; signInAudience = 'AzureADMyOrg'; createdDateTime = $null; passwordCredentialCount = 0 }
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

    function script:New-TestOwnerOfRelationship {
        param([string]$OwnerId, [string]$OwnedId)
        return [ordered]@{
            relationshipId = "$OwnerId::$OwnedId::OwnerOf"; sourceEntityId = $OwnerId; targetEntityId = $OwnedId
            relationshipType = 'OwnerOf'; assignmentState = 'Active'; scope = 'directory'
            provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }
            validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false }
        }
    }
}

Describe 'ENT-003: Test-EntraPostureEnterpriseAppOwnerTierControl' {
    It 'fails a service principal with a non-Tier-0 owner, passes one with only Tier-0 owners, and flags one with no owners' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principals.jsonl' -Records @(
            (New-TestServicePrincipalEntity -Id 'sp-weak'),
            (New-TestServicePrincipalEntity -Id 'sp-strong'),
            (New-TestServicePrincipalEntity -Id 'sp-orphan')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-owners.jsonl' -Records @(
            (New-TestOwnerOfRelationship -OwnerId 'owner-weak' -OwnedId 'sp-weak'),
            (New-TestOwnerOfRelationship -OwnerId 'owner-strong' -OwnedId 'sp-strong')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            (New-TestDirectoryRoleAssignmentRelationship -PrincipalId 'owner-strong' -RoleId 'ga-role')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureEnterpriseAppOwnerTierControl -EvidenceProvider $provider
        $result.Count | Should -Be 3
        ($result | Where-Object { $_.Scope -eq 'sp-weak' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'sp-strong' }).Status | Should -Be 'Pass'
        ($result | Where-Object { $_.Scope -eq 'sp-orphan' }).Status | Should -Be 'NotApplicable'
        ($result | Where-Object { $_.Scope -eq 'sp-orphan' }).ReasonCode | Should -Be 'ENT-003-NO-OWNERS'
    }

    It 'reports NotApplicable when no service principal exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureEnterpriseAppOwnerTierControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].ReasonCode | Should -Be 'ENT-003-NO-SERVICE-PRINCIPALS'
    }
}

Describe 'APP-003: Test-EntraPostureAppRegistrationOwnerTierControl' {
    It 'fails an application with a non-Tier-0 owner and passes one with only Tier-0 owners' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-applications.jsonl' -Records @(
            (New-TestApplicationEntity -Id 'app-weak'),
            (New-TestApplicationEntity -Id 'app-strong')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-owners.jsonl' -Records @(
            (New-TestOwnerOfRelationship -OwnerId 'owner-weak' -OwnedId 'app-weak'),
            (New-TestOwnerOfRelationship -OwnerId 'owner-strong' -OwnedId 'app-strong')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            (New-TestDirectoryRoleAssignmentRelationship -PrincipalId 'owner-strong' -RoleId 'ga-role')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAppRegistrationOwnerTierControl -EvidenceProvider $provider
        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Scope -eq 'app-weak' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'app-strong' }).Status | Should -Be 'Pass'
    }

    It 'reports NotApplicable when no application exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAppRegistrationOwnerTierControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].ReasonCode | Should -Be 'APP-003-NO-APPLICATIONS'
    }
}

Describe 'ENT-008: Test-EntraPostureForeignServicePrincipalOwnedObjectsControl' {
    It 'fails a foreign service principal that owns an object, passes one that owns nothing, ignores internal principals' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principals.jsonl' -Records @(
            (New-TestServicePrincipalEntity -Id 'sp-foreign-owner' -OwnerOrgId 't2'),
            (New-TestServicePrincipalEntity -Id 'sp-foreign-clean' -OwnerOrgId 't2'),
            (New-TestServicePrincipalEntity -Id 'sp-internal' -OwnerOrgId 't1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-owners.jsonl' -Records @(
            (New-TestOwnerOfRelationship -OwnerId 'sp-foreign-owner' -OwnedId 'owned-app-1'),
            (New-TestOwnerOfRelationship -OwnerId 'sp-internal' -OwnedId 'owned-app-2')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureForeignServicePrincipalOwnedObjectsControl -EvidenceProvider $provider
        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Scope -eq 'sp-foreign-owner' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'sp-foreign-clean' }).Status | Should -Be 'Pass'
    }

    It 'reports NotApplicable when no foreign service principal exists' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principals.jsonl' -Records @(
            (New-TestServicePrincipalEntity -Id 'sp-internal' -OwnerOrgId 't1')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureForeignServicePrincipalOwnedObjectsControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].ReasonCode | Should -Be 'ENT-008-NO-FOREIGN-SERVICE-PRINCIPALS'
    }
}
