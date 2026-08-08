#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 13 (agent identity / PIM-for-Groups): the 9 designable AGT-* controls
    plus PIMG-001/002, and the shared Get-EntraPostureAgentIdentityForeignMap/
    Get-EntraPostureAgentUserForeignMap correlation helpers, using the evidence-provider fixture
    pattern established in Phase 7/8's own control tests.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/AgentIdentityForeignDerivation.ps1',
        'src/Controls/EvaluateAgentBlueprintClientSecrets.ps1',
        'src/Controls/EvaluateForeignAgentIdentityEntraRole.ps1',
        'src/Controls/EvaluateForeignAgentIdentityAzureRole.ps1',
        'src/Controls/EvaluateInternalAgentIdentityEntraRole.ps1',
        'src/Controls/EvaluateInternalAgentIdentityAzureRole.ps1',
        'src/Controls/EvaluateForeignAgentUserEntraRole.ps1',
        'src/Controls/EvaluateForeignAgentUserAzureRole.ps1',
        'src/Controls/EvaluateAgentUserCapGroupOwnership.ps1',
        'src/Controls/EvaluateAgentBlueprintOwnerTier.ps1',
        'src/Controls/EvaluatePimForGroupsStandingMembership.ps1',
        'src/Controls/EvaluatePimForGroupsPermanentAssignment.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "agt-controls-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestBlueprintEntity {
        param([string]$Id, [int]$PasswordCredentialCount = 0)
        return [ordered]@{
            entityId = $Id; entityType = 'AgentIdentityBlueprint'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ appId = "app-$Id"; passwordCredentialCount = $PasswordCredentialCount }
        }
    }

    function script:New-TestBlueprintPrincipalEntity {
        param([string]$Id, [string]$AppId, [string]$OwnerOrgId)
        return [ordered]@{
            entityId = $Id; entityType = 'AgentIdentityBlueprintPrincipal'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ appId = $AppId; appOwnerOrganizationId = $OwnerOrgId; accountEnabled = $true }
        }
    }

    function script:New-TestAgentIdentityEntity {
        param([string]$Id, [string]$BlueprintAppId)
        return [ordered]@{
            entityId = $Id; entityType = 'AgentIdentity'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ agentIdentityBlueprintId = $BlueprintAppId; accountEnabled = $true }
        }
    }

    function script:New-TestAgentUserEntity {
        param([string]$Id, [string]$ParentId)
        return [ordered]@{
            entityId = $Id; entityType = 'AgentUser'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ identityParentId = $ParentId; accountEnabled = $true; userPrincipalName = "$Id@t1" }
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

    function script:New-TestOwnerOfRelationship {
        param([string]$OwnerId, [string]$OwnedId)
        return [ordered]@{
            relationshipId = "$OwnerId::$OwnedId::OwnerOf"; sourceEntityId = $OwnerId; targetEntityId = $OwnedId
            relationshipType = 'OwnerOf'; assignmentState = 'Active'; scope = 'directory'
            provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }
            validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $false }
        }
    }

    function script:New-TestCaPolicyWithGroupCondition {
        param([string]$Id, [string[]]$IncludeGroups = @())
        return [ordered]@{
            entityId = $Id; entityType = 'ConditionalAccessPolicy'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                state = 'enabled'; createdDateTime = $null; modifiedDateTime = $null
                conditions = [ordered]@{
                    clientAppTypes = @(); signInRiskLevels = @(); userRiskLevels = @()
                    users = [ordered]@{ includeUsers = @('All'); excludeUsers = @(); includeGroups = $IncludeGroups; excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
                    applications = [ordered]@{ includeApplications = @('All'); excludeApplications = @() }
                    platforms = [ordered]@{ includePlatforms = @(); excludePlatforms = @() }
                    locations = [ordered]@{ includeLocations = @(); excludeLocations = @() }
                    devices = [ordered]@{ deviceFilterMode = $null; deviceFilterRule = $null }
                }
                grantControls = [ordered]@{ operator = 'AND'; builtInControls = @('mfa'); authenticationStrengthId = $null }
            }
        }
    }

    function script:New-TestGroupEntity {
        param([string]$Id, [bool]$IsAssignableToRole = $true)
        return [ordered]@{
            entityId = $Id; entityType = 'Group'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ mailEnabled = $false; isAssignableToRole = $IsAssignableToRole }
        }
    }

    function script:New-TestTransitiveMemberOfRelationship {
        param([string]$PrincipalId, [string]$GroupId)
        return [ordered]@{
            relationshipId = "$PrincipalId::$GroupId::TransitiveMemberOf"; sourceEntityId = $PrincipalId; targetEntityId = $GroupId
            relationshipType = 'TransitiveMemberOf'; assignmentState = 'Active'; scope = 'directory'
            provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }
            validity = [ordered]@{ startDateTime = $null; endDateTime = $null; isTransitive = $true }
        }
    }

    function script:New-TestPimGroupRelationship {
        param([string]$Type, [string]$PrincipalId, [string]$GroupId, [string]$AccessId = 'member', $EndDateTime = $null)
        return [ordered]@{
            relationshipId = "$PrincipalId::$GroupId::$AccessId::$Type"; sourceEntityId = $PrincipalId; targetEntityId = $GroupId
            relationshipType = $Type; assignmentState = 'Active'; scope = $AccessId
            provenance = [ordered]@{ collectorVersion = '0.1.0'; sourceEndpoint = 'x'; collectedAt = '2026-01-01T00:00:00Z' }
            validity = [ordered]@{ startDateTime = '2026-01-01T00:00:00Z'; endDateTime = $EndDateTime; isTransitive = $false }
        }
    }
}

Describe 'AGT-001: Test-EntraPostureAgentBlueprintClientSecretControl' {
    It 'reports NotApplicable when no blueprint exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAgentBlueprintClientSecretControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
    }

    It 'fails a blueprint with a password credential and passes one without' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identity-blueprints.jsonl' -Records @(
            (New-TestBlueprintEntity -Id 'bp-secret' -PasswordCredentialCount 1),
            (New-TestBlueprintEntity -Id 'bp-clean' -PasswordCredentialCount 0)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAgentBlueprintClientSecretControl -EvidenceProvider $provider
        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Scope -eq 'bp-secret' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'bp-clean' }).Status | Should -Be 'Pass'
    }
}

Describe 'Get-EntraPostureAgentIdentityForeignMap / Get-EntraPostureAgentUserForeignMap' {
    It 'resolves foreign-ness through agentIdentityBlueprintId -> blueprint principal appId -> appOwnerOrganizationId' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identity-blueprint-principals.jsonl' -Records @(
            (New-TestBlueprintPrincipalEntity -Id 'bpp-foreign' -AppId 'app-foreign' -OwnerOrgId 'other-tenant'),
            (New-TestBlueprintPrincipalEntity -Id 'bpp-internal' -AppId 'app-internal' -OwnerOrgId 't1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identities.jsonl' -Records @(
            (New-TestAgentIdentityEntity -Id 'agt-foreign' -BlueprintAppId 'app-foreign'),
            (New-TestAgentIdentityEntity -Id 'agt-internal' -BlueprintAppId 'app-internal'),
            (New-TestAgentIdentityEntity -Id 'agt-unresolvable' -BlueprintAppId 'app-unknown')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $map = Get-EntraPostureAgentIdentityForeignMap -EvidenceProvider $provider
        $map['agt-foreign'] | Should -BeTrue
        $map['agt-internal'] | Should -BeFalse
        $map['agt-unresolvable'] | Should -Be $null
    }

    It 'derives an agent user''s foreign-ness transitively through identityParentId' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identity-blueprint-principals.jsonl' -Records @(
            (New-TestBlueprintPrincipalEntity -Id 'bpp-foreign' -AppId 'app-foreign' -OwnerOrgId 'other-tenant')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identities.jsonl' -Records @(
            (New-TestAgentIdentityEntity -Id 'agt-foreign' -BlueprintAppId 'app-foreign')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-users.jsonl' -Records @(
            (New-TestAgentUserEntity -Id 'au-foreign' -ParentId 'agt-foreign'),
            (New-TestAgentUserEntity -Id 'au-unresolvable' -ParentId 'agt-missing')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $map = Get-EntraPostureAgentUserForeignMap -EvidenceProvider $provider
        $map['au-foreign'] | Should -BeTrue
        $map['au-unresolvable'] | Should -Be $null
    }
}

Describe 'AGT-004/AGT-008: foreign/internal agent identity Tier-0 Entra role controls' {
    It 'AGT-004 fails a foreign agent identity holding a Tier-0 role and reports NotApplicable when none are foreign' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identity-blueprint-principals.jsonl' -Records @(
            (New-TestBlueprintPrincipalEntity -Id 'bpp-1' -AppId 'app-1' -OwnerOrgId 'other-tenant')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identities.jsonl' -Records @(
            (New-TestAgentIdentityEntity -Id 'agt-1' -BlueprintAppId 'app-1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            (New-TestDirectoryRoleAssignmentRelationship -PrincipalId 'agt-1' -RoleId 'ga-role')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureForeignAgentIdentityEntraRoleControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AGT-004-FOREIGN-TIER-ZERO-ROLE'
    }

    It 'AGT-008 passes an internal agent identity with no Tier-0 role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identity-blueprint-principals.jsonl' -Records @(
            (New-TestBlueprintPrincipalEntity -Id 'bpp-1' -AppId 'app-1' -OwnerOrgId 't1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identities.jsonl' -Records @(
            (New-TestAgentIdentityEntity -Id 'agt-1' -BlueprintAppId 'app-1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureInternalAgentIdentityEntraRoleControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'AGT-008-NO-TIER-ZERO-ROLE'
    }
}

Describe 'AGT-005/AGT-009: foreign/internal agent identity Azure role controls' {
    It 'AGT-005 fails a foreign agent identity holding any Azure role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identity-blueprint-principals.jsonl' -Records @(
            (New-TestBlueprintPrincipalEntity -Id 'bpp-1' -AppId 'app-1' -OwnerOrgId 'other-tenant')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identities.jsonl' -Records @(
            (New-TestAgentIdentityEntity -Id 'agt-1' -BlueprintAppId 'app-1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/azure-role-assignments.jsonl' -Records @(
            (New-TestAzureRoleAssignmentEntity -Id 'ara-1' -PrincipalId 'agt-1')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureForeignAgentIdentityAzureRoleControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
    }

    It 'AGT-009 reports NotApplicable when no agent identity is confirmed internal' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureInternalAgentIdentityAzureRoleControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
    }
}

Describe 'AGT-011/AGT-012: foreign agent user Entra/Azure role controls' {
    It 'AGT-011 fails a foreign agent user holding a Tier-0 role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identity-blueprint-principals.jsonl' -Records @(
            (New-TestBlueprintPrincipalEntity -Id 'bpp-1' -AppId 'app-1' -OwnerOrgId 'other-tenant')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identities.jsonl' -Records @(
            (New-TestAgentIdentityEntity -Id 'agt-1' -BlueprintAppId 'app-1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-users.jsonl' -Records @(
            (New-TestAgentUserEntity -Id 'au-1' -ParentId 'agt-1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            (New-TestDirectoryRoleAssignmentRelationship -PrincipalId 'au-1' -RoleId 'ga-role')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureForeignAgentUserEntraRoleControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AGT-011-FOREIGN-TIER-ZERO-ROLE'
    }

    It 'AGT-012 passes a foreign agent user with no Azure role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identity-blueprint-principals.jsonl' -Records @(
            (New-TestBlueprintPrincipalEntity -Id 'bpp-1' -AppId 'app-1' -OwnerOrgId 'other-tenant')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identities.jsonl' -Records @(
            (New-TestAgentIdentityEntity -Id 'agt-1' -BlueprintAppId 'app-1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-users.jsonl' -Records @(
            (New-TestAgentUserEntity -Id 'au-1' -ParentId 'agt-1')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureForeignAgentUserAzureRoleControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Pass'
    }
}

Describe 'AGT-015: Test-EntraPostureAgentUserCapGroupOwnershipControl' {
    It 'fails an agent user owning a CAP-referenced group and passes one owning only unreferenced groups' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-users.jsonl' -Records @(
            (New-TestAgentUserEntity -Id 'au-cap' -ParentId 'agt-1'),
            (New-TestAgentUserEntity -Id 'au-safe' -ParentId 'agt-2')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-owners.jsonl' -Records @(
            (New-TestOwnerOfRelationship -OwnerId 'au-cap' -OwnedId 'group-cap'),
            (New-TestOwnerOfRelationship -OwnerId 'au-safe' -OwnedId 'group-safe')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicyWithGroupCondition -Id 'ca1' -IncludeGroups @('group-cap'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAgentUserCapGroupOwnershipControl -EvidenceProvider $provider
        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Scope -eq 'au-cap' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'au-safe' }).Status | Should -Be 'Pass'
    }

    It 'reports NotApplicable when no agent user owns any group' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAgentUserCapGroupOwnershipControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
    }
}

Describe 'AGT-017: Test-EntraPostureAgentBlueprintOwnerTierControl' {
    It 'fails a blueprint with a non-Tier-0 owner, passes one with only Tier-0 owners, and flags one with no owners' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identity-blueprints.jsonl' -Records @(
            (New-TestBlueprintEntity -Id 'bp-weak'),
            (New-TestBlueprintEntity -Id 'bp-strong'),
            (New-TestBlueprintEntity -Id 'bp-orphan')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-owners.jsonl' -Records @(
            (New-TestOwnerOfRelationship -OwnerId 'owner-weak' -OwnedId 'bp-weak'),
            (New-TestOwnerOfRelationship -OwnerId 'owner-strong' -OwnedId 'bp-strong')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            (New-TestDirectoryRoleAssignmentRelationship -PrincipalId 'owner-strong' -RoleId 'ga-role')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAgentBlueprintOwnerTierControl -EvidenceProvider $provider
        $result.Count | Should -Be 3
        ($result | Where-Object { $_.Scope -eq 'bp-weak' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'bp-strong' }).Status | Should -Be 'Pass'
        ($result | Where-Object { $_.Scope -eq 'bp-orphan' }).Status | Should -Be 'NotApplicable'
        ($result | Where-Object { $_.Scope -eq 'bp-orphan' }).ReasonCode | Should -Be 'AGT-017-NO-OWNERS'
    }
}

Describe 'PIMG-001: Test-EntraPosturePimForGroupsStandingMembershipControl' {
    It 'fails a role-assignable group with a member PIM has no eligibility/active record for' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @(
            (New-TestGroupEntity -Id 'grp-1' -IsAssignableToRole $true)
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-memberships.jsonl' -Records @(
            (New-TestTransitiveMemberOfRelationship -PrincipalId 'user-known' -GroupId 'grp-1'),
            (New-TestTransitiveMemberOfRelationship -PrincipalId 'user-bypass' -GroupId 'grp-1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-pim-eligibility.jsonl' -Records @(
            (New-TestPimGroupRelationship -Type 'PimEligible' -PrincipalId 'user-known' -GroupId 'grp-1')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPosturePimForGroupsStandingMembershipControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'PIMG-001-STANDING-MEMBERSHIP-OUTSIDE-PIM'
    }

    It 'passes a group where every member is accounted for, and reports NotApplicable with no PIM configured' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @(
            (New-TestGroupEntity -Id 'grp-1' -IsAssignableToRole $true)
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-memberships.jsonl' -Records @(
            (New-TestTransitiveMemberOfRelationship -PrincipalId 'user-known' -GroupId 'grp-1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-pim-eligibility.jsonl' -Records @(
            (New-TestPimGroupRelationship -Type 'PimEligible' -PrincipalId 'user-known' -GroupId 'grp-1')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPosturePimForGroupsStandingMembershipControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Pass'

        $emptyDir = New-TestSnapshotDir
        $emptyProvider = New-EntraPostureEvidenceProvider -SnapshotPath $emptyDir
        $emptyResult = Test-EntraPosturePimForGroupsStandingMembershipControl -EvidenceProvider $emptyProvider
        $emptyResult.Count | Should -Be 1
        $emptyResult[0].Status | Should -Be 'NotApplicable'
    }
}

Describe 'PIMG-002: Test-EntraPosturePimForGroupsPermanentAssignmentControl' {
    It 'fails a group with a no-expiration active assignment and passes one where every assignment expires' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @(
            (New-TestGroupEntity -Id 'grp-permanent' -IsAssignableToRole $true),
            (New-TestGroupEntity -Id 'grp-bounded' -IsAssignableToRole $true)
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-pim-active-assignments.jsonl' -Records @(
            (New-TestPimGroupRelationship -Type 'PimActive' -PrincipalId 'user-1' -GroupId 'grp-permanent' -EndDateTime $null),
            (New-TestPimGroupRelationship -Type 'PimActive' -PrincipalId 'user-2' -GroupId 'grp-bounded' -EndDateTime '2026-06-01T00:00:00Z')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPosturePimForGroupsPermanentAssignmentControl -EvidenceProvider $provider
        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Scope -eq 'grp-permanent' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'grp-bounded' }).Status | Should -Be 'Pass'
    }

    It 'reports NotApplicable when no role-assignable group has a PIM-for-Groups active assignment' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPosturePimForGroupsPermanentAssignmentControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
    }
}
