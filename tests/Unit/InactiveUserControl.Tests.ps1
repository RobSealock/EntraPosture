#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2, new-evidence phase (batch 8, 2026-08-08): USR-005, the second
    control in this project's registry (after AR-002) whose evaluator compares against the wall
    clock at evaluation time rather than a static evidence field -- see the evaluator's own
    DESCRIPTION for why. Dates in this file are computed relative to [DateTime]::UtcNow so the
    tests remain valid regardless of when they run.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateInactiveUser.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "inactive-user-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestUserEntity {
        param([string]$Id, [string]$CreatedDateTime = $null)
        return [ordered]@{
            entityId = $Id; entityType = 'User'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                userPrincipalName = "$Id@contoso.com"; accountEnabled = $true; userType = 'Member'
                onPremisesSyncEnabled = $false; createdDateTime = $CreatedDateTime
            }
        }
    }

    function script:New-TestSignInActivityEntity {
        param([string]$Id, [string]$LastSuccessfulSignInDateTime = $null)
        return [ordered]@{
            entityId = $Id; entityType = 'UserSignInActivity'; tenantScope = 't1'; displayName = $null
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                lastSignInDateTime = $LastSuccessfulSignInDateTime; lastNonInteractiveSignInDateTime = $LastSuccessfulSignInDateTime
                lastSuccessfulSignInDateTime = $LastSuccessfulSignInDateTime
            }
        }
    }
}

Describe 'USR-005: Test-EntraPostureInactiveUserControl' {
    It 'fails a user last successfully signed in 200 days ago and passes one active 10 days ago' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-users.jsonl' -Records @(
            (New-TestUserEntity -Id 'user-stale'),
            (New-TestUserEntity -Id 'user-active')
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-user-sign-in-activity.jsonl' -Records @(
            (New-TestSignInActivityEntity -Id 'user-stale' -LastSuccessfulSignInDateTime ([DateTime]::UtcNow.AddDays(-200).ToString('o'))),
            (New-TestSignInActivityEntity -Id 'user-active' -LastSuccessfulSignInDateTime ([DateTime]::UtcNow.AddDays(-10).ToString('o')))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureInactiveUserControl -EvidenceProvider $provider
        $result.Count | Should -Be 2
        ($result | Where-Object { $_.Scope -eq 'user-stale' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'user-stale' }).ReasonCode | Should -Be 'USR-005-INACTIVE-SINCE-LAST-SIGN-IN'
        ($result | Where-Object { $_.Scope -eq 'user-active' }).Status | Should -Be 'Pass'
    }

    It 'falls back to account age when a user has never signed in' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-users.jsonl' -Records @(
            (New-TestUserEntity -Id 'user-old-never' -CreatedDateTime ([DateTime]::UtcNow.AddDays(-400).ToString('o'))),
            (New-TestUserEntity -Id 'user-new-never' -CreatedDateTime ([DateTime]::UtcNow.AddDays(-5).ToString('o')))
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-user-sign-in-activity.jsonl' -Records @(
            (New-TestSignInActivityEntity -Id 'user-old-never'),
            (New-TestSignInActivityEntity -Id 'user-new-never')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureInactiveUserControl -EvidenceProvider $provider
        ($result | Where-Object { $_.Scope -eq 'user-old-never' }).Status | Should -Be 'Fail'
        ($result | Where-Object { $_.Scope -eq 'user-old-never' }).ReasonCode | Should -Be 'USR-005-NEVER-SIGNED-IN'
        ($result | Where-Object { $_.Scope -eq 'user-new-never' }).Status | Should -Be 'Pass'
        ($result | Where-Object { $_.Scope -eq 'user-new-never' }).ReasonCode | Should -Be 'USR-005-NEW-ACCOUNT-NOT-YET-SIGNED-IN'
    }

    It 'passes with no temporal signal when neither sign-in nor createdDateTime is known' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-users.jsonl' -Records @(
            (New-TestUserEntity -Id 'user-unknown')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureInactiveUserControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'USR-005-NO-TEMPORAL-SIGNAL'
    }

    It 'reports NotApplicable when no user exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureInactiveUserControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].ReasonCode | Should -Be 'USR-005-NO-USERS'
    }
}
