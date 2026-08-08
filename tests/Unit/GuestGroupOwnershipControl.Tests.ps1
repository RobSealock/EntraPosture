#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2, new-evidence phase (batch 7, 2026-08-08): COL-003, the first
    control unlocked by the new GroupSettings collector.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateGuestGroupOwnership.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "guest-group-owner-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestGroupSettingEntity {
        param([string]$Id = 's1', [string]$DisplayName = 'Group.Unified', [object]$AllowGuestsToBeGroupOwner = $null)
        return [ordered]@{
            entityId = $Id; entityType = 'GroupSetting'; tenantScope = 't1'; displayName = $DisplayName
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ templateId = '62375ab9-6b52-47ed-826b-58e47e0e304b'; allowGuestsToBeGroupOwner = $AllowGuestsToBeGroupOwner }
        }
    }
}

Describe 'COL-003: Test-EntraPostureGuestGroupOwnershipControl' {
    It 'fails when Group.Unified explicitly allows guests to be group owners' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-settings.jsonl' -Records @(
            (New-TestGroupSettingEntity -AllowGuestsToBeGroupOwner $true)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureGuestGroupOwnershipControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'COL-003-GUESTS-ALLOWED-GROUP-OWNER'
    }

    It 'passes when Group.Unified explicitly disallows guest group ownership' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-settings.jsonl' -Records @(
            (New-TestGroupSettingEntity -AllowGuestsToBeGroupOwner $false)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureGuestGroupOwnershipControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'COL-003-GUESTS-NOT-ALLOWED-GROUP-OWNER'
    }

    It 'passes on the documented default when no Group.Unified settings object exists at all' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureGuestGroupOwnershipControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'COL-003-DEFAULT-GUESTS-NOT-ALLOWED'
    }

    It 'ignores a non-Group.Unified settings object and falls back to the documented default' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-group-settings.jsonl' -Records @(
            (New-TestGroupSettingEntity -Id 's2' -DisplayName 'Group.Unified.Guest' -AllowGuestsToBeGroupOwner $null)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureGuestGroupOwnershipControl -EvidenceProvider $provider
        $result[0].ReasonCode | Should -Be 'COL-003-DEFAULT-GUESTS-NOT-ALLOWED'
    }
}
