#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2/13 follow-up (2026-08-08): MAI-002/003 (Managed Identities with
    Privileged Entra ID/Azure Roles -- no foreign/internal split, zero new evidence) and
    AGT-013/014 (Internal Agent Users with Privileged Entra ID/Azure Roles -- resolved from
    "blocked" to built, same evaluator shape as AGT-011/012's foreign counterpart).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/AgentIdentityForeignDerivation.ps1',
        'src/Controls/EvaluateManagedIdentityEntraRole.ps1',
        'src/Controls/EvaluateManagedIdentityAzureRole.ps1',
        'src/Controls/EvaluateInternalAgentUserEntraRole.ps1',
        'src/Controls/EvaluateInternalAgentUserAzureRole.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "mai-agt-controls-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestManagedIdentityEntity {
        param([string]$Id)
        return [ordered]@{
            entityId = $Id; entityType = 'ManagedIdentity'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ appId = "app-$Id"; servicePrincipalType = 'ManagedIdentity'; accountEnabled = $true }
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
}

Describe 'MAI-002: Test-EntraPostureManagedIdentityEntraRoleControl' {
    It 'reports NotApplicable when no managed identity exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureManagedIdentityEntraRoleControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
    }

    It 'fails a managed identity holding a Tier-0 role and passes one that does not' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-managed-identities.jsonl' -Records @(
            (New-TestManagedIdentityEntity -Id 'mi-priv'), (New-TestManagedIdentityEntity -Id 'mi-clean')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-assignments.jsonl' -Records @(
            (New-TestDirectoryRoleAssignmentRelationship -PrincipalId 'mi-priv' -RoleId 'ga-role')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureManagedIdentityEntraRoleControl -EvidenceProvider $provider
        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Scope -eq 'mi-priv' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'mi-clean' }).Status | Should -Be 'Pass'
    }
}

Describe 'MAI-003: Test-EntraPostureManagedIdentityAzureRoleControl' {
    It 'fails a managed identity holding any Azure role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-managed-identities.jsonl' -Records @((New-TestManagedIdentityEntity -Id 'mi-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/azure-role-assignments.jsonl' -Records @((New-TestAzureRoleAssignmentEntity -Id 'ara-1' -PrincipalId 'mi-1'))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureManagedIdentityAzureRoleControl -EvidenceProvider $provider)[0].Status | Should -Be 'Fail'
    }
}

Describe 'AGT-013/AGT-014: internal agent user Entra/Azure role controls' {
    It 'AGT-013 fails an internal agent user holding a Tier-0 role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identity-blueprint-principals.jsonl' -Records @(
            (New-TestBlueprintPrincipalEntity -Id 'bpp-1' -AppId 'app-1' -OwnerOrgId 't1')
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
        $result = Test-EntraPostureInternalAgentUserEntraRoleControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'AGT-013-INTERNAL-TIER-ZERO-ROLE'
    }

    It 'AGT-014 reports NotApplicable when no agent user is confirmed internal' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureInternalAgentUserAzureRoleControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
    }
}
