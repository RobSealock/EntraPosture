#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2, new-evidence phase (the "Extensive API Privileges" architecture-
    fork item, resolved 2026-08-08, by explicit project owner decision, as a general service-
    principal-permission-risk control): the shared Get-EntraPostureExtensiveApiPrivilegeControlResult
    helper (ExtensiveApiPrivilege.ps1) and all nine thin-wrapper controls that reuse it
    (ENT-004/005/009/010, AGT-002/003/006/007, MAI-001).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/AgentIdentityForeignDerivation.ps1',
        'src/Controls/ApiPermissionRiskList.ps1',
        'src/Controls/ExtensiveApiPrivilege.ps1',
        'src/Controls/EvaluateForeignEnterpriseAppExtensiveApiApplicationPrivilege.ps1',
        'src/Controls/EvaluateForeignEnterpriseAppExtensiveApiDelegatedPrivilege.ps1',
        'src/Controls/EvaluateInternalEnterpriseAppExtensiveApiApplicationPrivilege.ps1',
        'src/Controls/EvaluateInternalEnterpriseAppExtensiveApiDelegatedPrivilege.ps1',
        'src/Controls/EvaluateForeignAgentIdentityExtensiveApiApplicationPrivilege.ps1',
        'src/Controls/EvaluateForeignAgentIdentityExtensiveApiDelegatedPrivilege.ps1',
        'src/Controls/EvaluateInternalAgentIdentityExtensiveApiApplicationPrivilege.ps1',
        'src/Controls/EvaluateInternalAgentIdentityExtensiveApiDelegatedPrivilege.ps1',
        'src/Controls/EvaluateManagedIdentityExtensiveApiPrivilege.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    $script:DangerousAppRoleId = (Get-EntraPostureDangerousApplicationPermissionId)[0]
    $script:DangerousDelegatedScope = (Get-EntraPostureDangerousDelegatedPermissionName)[0]

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "extensive-api-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestServicePrincipalEntity {
        param([string]$Id, [string]$OwnerOrgId = $null, [string]$EntityType = 'ServicePrincipal')
        return [ordered]@{
            entityId = $Id; entityType = $EntityType; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ appId = "app-$Id"; servicePrincipalType = 'Application'; accountEnabled = $true; appOwnerOrganizationId = $OwnerOrgId }
        }
    }

    function script:New-TestApiPermissionsEntity {
        param([string]$Id, [string[]]$AppRoleIds = @(), [string[]]$DelegatedScopes = @())
        return [ordered]@{
            entityId = $Id; entityType = 'ServicePrincipalApiPermissions'; tenantScope = 't1'; displayName = $null
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ applicationPermissionAppRoleIds = $AppRoleIds; delegatedPermissionScopes = $DelegatedScopes }
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
}

Describe 'Get-EntraPostureExtensiveApiPrivilegeControlResult: ServicePrincipal population' {
    It 'fails a foreign service principal with a dangerous application permission, passes a clean one' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principals.jsonl' -Records @(
            (New-TestServicePrincipalEntity -Id 'sp-foreign-bad' -OwnerOrgId 't2'),
            (New-TestServicePrincipalEntity -Id 'sp-foreign-clean' -OwnerOrgId 't2'),
            (New-TestServicePrincipalEntity -Id 'sp-internal' -OwnerOrgId 't1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principal-api-permissions.jsonl' -Records @(
            (New-TestApiPermissionsEntity -Id 'sp-foreign-bad' -AppRoleIds @($script:DangerousAppRoleId))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Get-EntraPostureExtensiveApiPrivilegeControlResult -EvidenceProvider $provider `
            -PermissionType 'Application' -PopulationEntityType 'ServicePrincipal' -ForeignFilter 'Foreign' `
            -ControlId 'ENT-004' -PopulationLabel 'foreign enterprise application'
        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Scope -eq 'sp-foreign-bad' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'sp-foreign-bad' }).ReasonCode | Should -Be 'ENT-004-EXTENSIVE-PRIVILEGE'
        ($result | Where-Object { $_.Scope -eq 'sp-foreign-clean' }).Status | Should -Be 'Pass'
    }

    It 'fails an internal service principal with a dangerous delegated permission' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principals.jsonl' -Records @(
            (New-TestServicePrincipalEntity -Id 'sp-internal-bad' -OwnerOrgId 't1')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principal-api-permissions.jsonl' -Records @(
            (New-TestApiPermissionsEntity -Id 'sp-internal-bad' -DelegatedScopes @($script:DangerousDelegatedScope))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Get-EntraPostureExtensiveApiPrivilegeControlResult -EvidenceProvider $provider `
            -PermissionType 'Delegated' -PopulationEntityType 'ServicePrincipal' -ForeignFilter 'Internal' `
            -ControlId 'ENT-010' -PopulationLabel 'internal enterprise application'
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'ENT-010-EXTENSIVE-PRIVILEGE'
    }

    It 'reports NotApplicable when the population is empty' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Get-EntraPostureExtensiveApiPrivilegeControlResult -EvidenceProvider $provider `
            -PermissionType 'Application' -PopulationEntityType 'ServicePrincipal' -ForeignFilter 'Foreign' `
            -ControlId 'ENT-004' -PopulationLabel 'foreign enterprise application'
        $result.Count | Should -Be 1
        $result[0].ReasonCode | Should -Be 'ENT-004-NO-CANDIDATES'
    }
}

Describe 'Get-EntraPostureExtensiveApiPrivilegeControlResult: AgentIdentity population' {
    It 'fails a foreign agent identity and passes an internal one, each with a dangerous application permission' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identities.jsonl' -Records @(
            (New-TestAgentIdentityEntity -Id 'agent-foreign' -BlueprintAppId 'bp-app-foreign'),
            (New-TestAgentIdentityEntity -Id 'agent-internal' -BlueprintAppId 'bp-app-internal')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-agent-identity-blueprint-principals.jsonl' -Records @(
            (New-TestBlueprintPrincipalEntity -Id 'bp-1' -AppId 'bp-app-foreign' -OwnerOrgId 't2'),
            (New-TestBlueprintPrincipalEntity -Id 'bp-2' -AppId 'bp-app-internal' -OwnerOrgId $null)
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principal-api-permissions.jsonl' -Records @(
            (New-TestApiPermissionsEntity -Id 'agent-foreign' -AppRoleIds @($script:DangerousAppRoleId)),
            (New-TestApiPermissionsEntity -Id 'agent-internal' -AppRoleIds @($script:DangerousAppRoleId))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir

        $foreignResult = Get-EntraPostureExtensiveApiPrivilegeControlResult -EvidenceProvider $provider `
            -PermissionType 'Application' -PopulationEntityType 'AgentIdentity' -ForeignFilter 'Foreign' `
            -ControlId 'AGT-002' -PopulationLabel 'foreign agent identity'
        $foreignResult.Count | Should -Be 1
        $foreignResult[0].Scope | Should -Be 'agent-foreign'
        $foreignResult[0].Status | Should -Be 'Fail'

        $internalResult = Get-EntraPostureExtensiveApiPrivilegeControlResult -EvidenceProvider $provider `
            -PermissionType 'Application' -PopulationEntityType 'AgentIdentity' -ForeignFilter 'Internal' `
            -ControlId 'AGT-006' -PopulationLabel 'internal agent identity'
        $internalResult.Count | Should -Be 1
        $internalResult[0].Scope | Should -Be 'agent-internal'
        $internalResult[0].Status | Should -Be 'Fail'
    }
}

Describe 'Get-EntraPostureExtensiveApiPrivilegeControlResult: ManagedIdentity population' {
    It 'fails a managed identity with a dangerous application permission, no foreign/internal split' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-managed-identities.jsonl' -Records @(
            (New-TestServicePrincipalEntity -Id 'mi-1' -EntityType 'ManagedIdentity')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principal-api-permissions.jsonl' -Records @(
            (New-TestApiPermissionsEntity -Id 'mi-1' -AppRoleIds @($script:DangerousAppRoleId))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Get-EntraPostureExtensiveApiPrivilegeControlResult -EvidenceProvider $provider `
            -PermissionType 'Application' -PopulationEntityType 'ManagedIdentity' -ForeignFilter 'All' `
            -ControlId 'MAI-001' -PopulationLabel 'managed identity'
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'MAI-001-EXTENSIVE-PRIVILEGE'
    }
}

Describe 'Thin wrapper wiring for all nine Extensive API Privileges controls' {
    It 'each wrapper delegates to the shared evaluator with its own fixed ControlId' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir

        $wrappers = @(
            @{ Function = 'Test-EntraPostureForeignEnterpriseAppExtensiveApiApplicationPrivilegeControl'; ReasonCode = 'ENT-004-NO-CANDIDATES' }
            @{ Function = 'Test-EntraPostureForeignEnterpriseAppExtensiveApiDelegatedPrivilegeControl'; ReasonCode = 'ENT-005-NO-CANDIDATES' }
            @{ Function = 'Test-EntraPostureInternalEnterpriseAppExtensiveApiApplicationPrivilegeControl'; ReasonCode = 'ENT-009-NO-CANDIDATES' }
            @{ Function = 'Test-EntraPostureInternalEnterpriseAppExtensiveApiDelegatedPrivilegeControl'; ReasonCode = 'ENT-010-NO-CANDIDATES' }
            @{ Function = 'Test-EntraPostureForeignAgentIdentityExtensiveApiApplicationPrivilegeControl'; ReasonCode = 'AGT-002-NO-CANDIDATES' }
            @{ Function = 'Test-EntraPostureForeignAgentIdentityExtensiveApiDelegatedPrivilegeControl'; ReasonCode = 'AGT-003-NO-CANDIDATES' }
            @{ Function = 'Test-EntraPostureInternalAgentIdentityExtensiveApiApplicationPrivilegeControl'; ReasonCode = 'AGT-006-NO-CANDIDATES' }
            @{ Function = 'Test-EntraPostureInternalAgentIdentityExtensiveApiDelegatedPrivilegeControl'; ReasonCode = 'AGT-007-NO-CANDIDATES' }
            @{ Function = 'Test-EntraPostureManagedIdentityExtensiveApiPrivilegeControl'; ReasonCode = 'MAI-001-NO-CANDIDATES' }
        )

        foreach ($wrapper in $wrappers) {
            $result = & $wrapper.Function -EvidenceProvider $provider
            $result.Count | Should -Be 1
            $result[0].ReasonCode | Should -Be $wrapper.ReasonCode
        }
    }
}
