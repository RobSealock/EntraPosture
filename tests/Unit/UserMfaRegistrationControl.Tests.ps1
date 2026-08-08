#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2, the 109-row backlog continuation (batch 12, 2026-08-08): USR-012,
    the first control unlocked by the new UserRegistrationDetails collector.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateUserMfaRegistration.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "usr-mfa-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestRegistrationDetailsEntity {
        param([string]$Id, [object]$IsMfaRegistered = $null)
        return [ordered]@{
            entityId = $Id; entityType = 'UserRegistrationDetails'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                isAdmin = $false; isMfaRegistered = $IsMfaRegistered; isMfaCapable = $IsMfaRegistered
                isPasswordlessCapable = $false; isSsprRegistered = $false; isSsprEnabled = $false; isSsprCapable = $false
                methodsRegistered = @(); userType = 'member'
            }
        }
    }
}

Describe 'USR-012: Test-EntraPostureUserMfaRegistrationControl' {
    It 'fails a user without MFA registered, passes one with it' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-user-registration-details.jsonl' -Records @(
            (New-TestRegistrationDetailsEntity -Id 'u-no-mfa' -IsMfaRegistered $false),
            (New-TestRegistrationDetailsEntity -Id 'u-mfa' -IsMfaRegistered $true)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureUserMfaRegistrationControl -EvidenceProvider $provider
        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Scope -eq 'u-no-mfa' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'u-no-mfa' }).ReasonCode | Should -Be 'USR-012-NO-MFA-REGISTERED'
        ($result | Where-Object { $_.Scope -eq 'u-mfa' }).Status | Should -Be 'Pass'
    }

    It 'reports NotApplicable when no registration details exist' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureUserMfaRegistrationControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].ReasonCode | Should -Be 'USR-012-NO-REGISTRATION-DETAILS'
    }
}
