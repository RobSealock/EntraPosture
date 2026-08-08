#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2 (zero-new-evidence matrix-row slice, batch 5 -- the confirm-medium
    pass, 2026-08-08): ENT-001 (service principal key/password credentials) and APP-002 (App
    Instance Property Lock, multitenant applications only).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateEnterpriseAppClientCredentials.ps1',
        'src/Controls/EvaluateAppInstancePropertyLock.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "ent-app-lock-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestServicePrincipalEntity {
        param([string]$Id, [int]$KeyCredentialCount = 0, [int]$PasswordCredentialCount = 0)
        return [ordered]@{
            entityId = $Id; entityType = 'ServicePrincipal'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                appId = "app-$Id"; servicePrincipalType = 'Application'; accountEnabled = $true; appOwnerOrganizationId = 't1'
                keyCredentialCount = $KeyCredentialCount; passwordCredentialCount = $PasswordCredentialCount
            }
        }
    }

    function script:New-TestApplicationEntity {
        param([string]$Id, [string]$SignInAudience = 'AzureADMyOrg', [bool]$LockEnabled = $false)
        return [ordered]@{
            entityId = $Id; entityType = 'Application'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                appId = "app-$Id"; signInAudience = $SignInAudience; createdDateTime = $null
                passwordCredentialCount = 0; appInstancePropertyLockEnabled = $LockEnabled
            }
        }
    }
}

Describe 'ENT-001: Test-EntraPostureEnterpriseAppClientCredentialsControl' {
    It 'fails a service principal with a key credential and one with a password credential, passes a clean one' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-service-principals.jsonl' -Records @(
            (New-TestServicePrincipalEntity -Id 'sp-key' -KeyCredentialCount 1),
            (New-TestServicePrincipalEntity -Id 'sp-pwd' -PasswordCredentialCount 1),
            (New-TestServicePrincipalEntity -Id 'sp-clean')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureEnterpriseAppClientCredentialsControl -EvidenceProvider $provider
        ($result | Where-Object { $_.Scope -eq 'sp-key' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'sp-pwd' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'sp-clean' }).Status | Should -Be 'Pass'
    }

    It 'reports NotApplicable when no service principal exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        (Test-EntraPostureEnterpriseAppClientCredentialsControl -EvidenceProvider $provider)[0].Status | Should -Be 'NotApplicable'
    }
}

Describe 'APP-002: Test-EntraPostureAppInstancePropertyLockControl' {
    It 'fails a multitenant app without the lock and passes one with it enabled' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-applications.jsonl' -Records @(
            (New-TestApplicationEntity -Id 'app-unlocked' -SignInAudience 'AzureADMultipleOrgs' -LockEnabled $false),
            (New-TestApplicationEntity -Id 'app-locked' -SignInAudience 'AzureADMultipleOrgs' -LockEnabled $true)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAppInstancePropertyLockControl -EvidenceProvider $provider
        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Scope -eq 'app-unlocked' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'app-locked' }).Status | Should -Be 'Pass'
    }

    It 'excludes single-tenant applications from the population entirely' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-applications.jsonl' -Records @(
            (New-TestApplicationEntity -Id 'app-single' -SignInAudience 'AzureADMyOrg' -LockEnabled $false)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAppInstancePropertyLockControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'APP-002-NO-MULTITENANT-APPLICATIONS'
    }
}
