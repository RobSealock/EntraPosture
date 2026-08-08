#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 10 (drift detection, deliberately built last per the project owner's
    own explicit instruction this session): Get-EntraPostureFieldDifference (the generic
    recursive diff primitive) and Compare-EntraPostureConditionalAccessDrift (the CA-specific
    policy/expected-case drift comparison built on top of it).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/ConditionalAccess/ScenarioModel.ps1',
        'src/ConditionalAccess/GenerateCombinatorialScenarios.ps1',
        'src/Reporting/CompareConditionalAccessDrift.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "ca-drift-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestCaPolicyEntity {
        param(
            [string]$Id, [string]$DisplayName = $Id, [string]$State = 'enabled',
            [string[]]$IncludeUsers = @('All'), [string[]]$IncludeGroups = @(),
            [string[]]$Platforms = @(), [string[]]$BuiltInControls = @('mfa')
        )
        return [ordered]@{
            entityId = $Id; entityType = 'ConditionalAccessPolicy'; tenantScope = 't1'; displayName = $DisplayName
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                state = $State; createdDateTime = $null; modifiedDateTime = $null
                conditions = [ordered]@{
                    clientAppTypes = @(); signInRiskLevels = @(); userRiskLevels = @()
                    users = [ordered]@{ includeUsers = $IncludeUsers; excludeUsers = @(); includeGroups = $IncludeGroups; excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
                    applications = [ordered]@{ includeApplications = @('All'); excludeApplications = @() }
                    platforms = [ordered]@{ includePlatforms = $Platforms; excludePlatforms = @() }
                    locations = [ordered]@{ includeLocations = @(); excludeLocations = @() }
                    devices = [ordered]@{ deviceFilterMode = $null; deviceFilterRule = $null }
                }
                grantControls = [ordered]@{ operator = 'AND'; builtInControls = $BuiltInControls; authenticationStrengthId = $null }
            }
        }
    }

    function script:New-TestGaRoleEntity {
        return [ordered]@{
            entityId = 'ga-role'; entityType = 'DirectoryRole'; tenantScope = 't1'; displayName = 'Global Administrator'
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; properties = [ordered]@{}; redacted = $false
        }
    }
}

Describe 'Get-EntraPostureFieldDifference' {
    It 'reports no diff for identical scalars and nested dictionaries' {
        $old = [ordered]@{ a = 'x'; b = [ordered]@{ c = 1 } }
        $new = [ordered]@{ a = 'x'; b = [ordered]@{ c = 1 } }
        # No @() wrapper -- Get-EntraPostureFieldDifference already comma-protects its return;
        # wrapping the call site double-wraps a genuinely empty result into a 1-element array
        # containing the real empty array (Count 1, not 0) -- the same bug class this session
        # already hit and fixed at four other call sites, caught here by this exact test failing.
        $diffs = Get-EntraPostureFieldDifference -OldValue $old -NewValue $new
        $diffs.Count | Should -Be 0
    }

    It 'reports a scalar change with the correct field path' {
        $old = [ordered]@{ state = 'enabled' }
        $new = [ordered]@{ state = 'disabled' }
        $diffs = Get-EntraPostureFieldDifference -OldValue $old -NewValue $new
        $diffs.Count | Should -Be 1
        $diffs[0].FieldPath | Should -Be 'state'
        $diffs[0].OldValue | Should -Be 'enabled'
        $diffs[0].NewValue | Should -Be 'disabled'
    }

    It 'treats arrays as unordered sets -- same membership in a different order is not a diff' {
        $old = [ordered]@{ includePlatforms = @('windows', 'iOS') }
        $new = [ordered]@{ includePlatforms = @('iOS', 'windows') }
        $diffs = Get-EntraPostureFieldDifference -OldValue $old -NewValue $new
        $diffs.Count | Should -Be 0
    }

    It 'reports an array diff when membership actually differs' {
        $old = [ordered]@{ includePlatforms = @('windows') }
        $new = [ordered]@{ includePlatforms = @('windows', 'iOS') }
        $diffs = Get-EntraPostureFieldDifference -OldValue $old -NewValue $new
        $diffs.Count | Should -Be 1
        $diffs[0].FieldPath | Should -Be 'includePlatforms'
    }

    It 'recurses into nested dictionaries with dotted field paths' {
        $old = [ordered]@{ conditions = [ordered]@{ users = [ordered]@{ includeUsers = @('All') } } }
        $new = [ordered]@{ conditions = [ordered]@{ users = [ordered]@{ includeUsers = @('user-1') } } }
        $diffs = Get-EntraPostureFieldDifference -OldValue $old -NewValue $new
        $diffs.Count | Should -Be 1
        $diffs[0].FieldPath | Should -Be 'conditions.users.includeUsers'
    }

    It 'reports a key present on only one side as a change to/from null' {
        $old = [ordered]@{ a = 'x' }
        $new = [ordered]@{ a = 'x'; b = 'y' }
        $diffs = Get-EntraPostureFieldDifference -OldValue $old -NewValue $new
        $diffs.Count | Should -Be 1
        $diffs[0].FieldPath | Should -Be 'b'
        $diffs[0].OldValue | Should -BeNullOrEmpty
        $diffs[0].NewValue | Should -Be 'y'
    }
}

Describe 'Compare-EntraPostureConditionalAccessDrift: policy-level structural drift' {
    It 'reports PolicyAdded for a policy present only in the new snapshot' {
        $oldDir = New-TestSnapshotDir
        $newDir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $newDir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicyEntity -Id 'p1'))
        $oldProvider = New-EntraPostureEvidenceProvider -SnapshotPath $oldDir
        $newProvider = New-EntraPostureEvidenceProvider -SnapshotPath $newDir

        $result = Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldProvider -NewEvidenceProvider $newProvider -OldSnapshotId 'old' -NewSnapshotId 'new'
        $added = @($result.DriftEvents | Where-Object { $_.category -eq 'PolicyAdded' })
        $added.Count | Should -Be 1
        $added[0].entityId | Should -Be 'p1'
        $added[0].affectedControlIds | Should -Contain 'CA-001'
        $added[0].affectedControlIds | Should -Contain 'CA-002'
    }

    It 'reports PolicyRemoved for a policy present only in the old snapshot' {
        $oldDir = New-TestSnapshotDir
        $newDir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $oldDir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicyEntity -Id 'p1'))
        $oldProvider = New-EntraPostureEvidenceProvider -SnapshotPath $oldDir
        $newProvider = New-EntraPostureEvidenceProvider -SnapshotPath $newDir

        $result = Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldProvider -NewEvidenceProvider $newProvider -OldSnapshotId 'old' -NewSnapshotId 'new'
        $removed = @($result.DriftEvents | Where-Object { $_.category -eq 'PolicyRemoved' })
        $removed.Count | Should -Be 1
        $removed[0].entityId | Should -Be 'p1'
    }

    It 'reports PolicyModified with field changes when a non-scope field changes, isScopeChange false' {
        $oldDir = New-TestSnapshotDir
        $newDir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $oldDir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicyEntity -Id 'p1' -BuiltInControls @('mfa')))
        Write-TestEvidenceFile -Dir $newDir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicyEntity -Id 'p1' -BuiltInControls @('mfa', 'compliantDevice')))
        $oldProvider = New-EntraPostureEvidenceProvider -SnapshotPath $oldDir
        $newProvider = New-EntraPostureEvidenceProvider -SnapshotPath $newDir

        $result = Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldProvider -NewEvidenceProvider $newProvider -OldSnapshotId 'old' -NewSnapshotId 'new'
        $modified = @($result.DriftEvents | Where-Object { $_.category -eq 'PolicyModified' })
        $modified.Count | Should -Be 1
        $modified[0].isScopeChange | Should -BeFalse
        @($modified[0].fieldChanges | Where-Object { $_.FieldPath -eq 'grantControls.builtInControls' }).Count | Should -Be 1
    }

    It 'flags isScopeChange true when a conditions.users field changes' {
        $oldDir = New-TestSnapshotDir
        $newDir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $oldDir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicyEntity -Id 'p1' -IncludeUsers @('All')))
        Write-TestEvidenceFile -Dir $newDir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicyEntity -Id 'p1' -IncludeUsers @('user-1')))
        $oldProvider = New-EntraPostureEvidenceProvider -SnapshotPath $oldDir
        $newProvider = New-EntraPostureEvidenceProvider -SnapshotPath $newDir

        $result = Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldProvider -NewEvidenceProvider $newProvider -OldSnapshotId 'old' -NewSnapshotId 'new'
        $modified = @($result.DriftEvents | Where-Object { $_.category -eq 'PolicyModified' })
        $modified[0].isScopeChange | Should -BeTrue
    }

    It 'reports no drift event for an unchanged policy' {
        $oldDir = New-TestSnapshotDir
        $newDir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $oldDir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicyEntity -Id 'p1'))
        Write-TestEvidenceFile -Dir $newDir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicyEntity -Id 'p1'))
        $oldProvider = New-EntraPostureEvidenceProvider -SnapshotPath $oldDir
        $newProvider = New-EntraPostureEvidenceProvider -SnapshotPath $newDir

        $result = Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldProvider -NewEvidenceProvider $newProvider -OldSnapshotId 'old' -NewSnapshotId 'new'
        @($result.DriftEvents | Where-Object { $_.entityType -eq 'ConditionalAccessPolicy' }).Count | Should -Be 0
    }

    It 'correlates a drift event with a related result transition via EvidenceReferences' {
        $oldDir = New-TestSnapshotDir
        $newDir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $newDir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicyEntity -Id 'p1'))
        $oldProvider = New-EntraPostureEvidenceProvider -SnapshotPath $oldDir
        $newProvider = New-EntraPostureEvidenceProvider -SnapshotPath $newDir

        $resultTransitions = @(
            [ordered]@{
                ControlId = 'CA-001'; Scope = 'windows::browser'; OldStatus = 'Fail'; NewStatus = 'Pass'
                EvidenceReferences = @([ordered]@{ entityId = 'p1'; entityType = 'ConditionalAccessPolicy' })
            }
        )
        $result = Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldProvider -NewEvidenceProvider $newProvider `
            -OldSnapshotId 'old' -NewSnapshotId 'new' -ResultTransitions $resultTransitions

        $added = @($result.DriftEvents | Where-Object { $_.category -eq 'PolicyAdded' })
        $added[0].relatedResultTransitions.Count | Should -Be 1
        $added[0].relatedResultTransitions[0].ControlId | Should -Be 'CA-001'
        $added[0].relatedResultTransitions[0].OldStatus | Should -Be 'Fail'
        $added[0].relatedResultTransitions[0].NewStatus | Should -Be 'Pass'
    }
}

Describe 'Compare-EntraPostureConditionalAccessDrift: expected-case drift (CA-002)' {
    It 'reports ExpectedCaseAdded when a new policy introduces a distinguishing platform value' {
        $oldDir = New-TestSnapshotDir
        $newDir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $oldDir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $newDir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $newDir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicyEntity -Id 'p1' -Platforms @('windows')))
        $oldProvider = New-EntraPostureEvidenceProvider -SnapshotPath $oldDir
        $newProvider = New-EntraPostureEvidenceProvider -SnapshotPath $newDir

        $result = Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldProvider -NewEvidenceProvider $newProvider -OldSnapshotId 'old' -NewSnapshotId 'new'
        $result.ExpectedCaseAnalysisSkipped | Should -BeFalse
        $added = @($result.DriftEvents | Where-Object { $_.category -eq 'ExpectedCaseAdded' })
        $added.Count | Should -BeGreaterThan 0
        ($added.entityId -like '*windows*').Count | Should -BeGreaterThan 0
        ($added.affectedControlIds | Select-Object -Unique) | Should -Be @('CA-002')
    }

    It 'reports ExpectedCaseRemoved when the curated Tier-0 role disappears entirely' {
        $oldDir = New-TestSnapshotDir
        $newDir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $oldDir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        # New snapshot has no DirectoryRole evidence at all -- role deactivated.
        $oldProvider = New-EntraPostureEvidenceProvider -SnapshotPath $oldDir
        $newProvider = New-EntraPostureEvidenceProvider -SnapshotPath $newDir

        $result = Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldProvider -NewEvidenceProvider $newProvider -OldSnapshotId 'old' -NewSnapshotId 'new'
        $removed = @($result.DriftEvents | Where-Object { $_.category -eq 'ExpectedCaseRemoved' })
        $removed.Count | Should -BeGreaterThan 0
    }

    It 'reports no expected-case drift when nothing distinguishing changed' {
        $oldDir = New-TestSnapshotDir
        $newDir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $oldDir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $newDir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        $oldProvider = New-EntraPostureEvidenceProvider -SnapshotPath $oldDir
        $newProvider = New-EntraPostureEvidenceProvider -SnapshotPath $newDir

        $result = Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldProvider -NewEvidenceProvider $newProvider -OldSnapshotId 'old' -NewSnapshotId 'new'
        @($result.DriftEvents | Where-Object { $_.category -like 'ExpectedCase*' }).Count | Should -Be 0
    }

    It 'confirms the clean-run baseline: skip flag false and reason null when nothing exceeds the bound' {
        $oldDir = New-TestSnapshotDir
        $newDir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $oldDir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $newDir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        $oldProvider = New-EntraPostureEvidenceProvider -SnapshotPath $oldDir
        $newProvider = New-EntraPostureEvidenceProvider -SnapshotPath $newDir
        $result = Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldProvider -NewEvidenceProvider $newProvider -OldSnapshotId 'old' -NewSnapshotId 'new'
        $result.ExpectedCaseAnalysisSkipped | Should -BeFalse
        $result.ExpectedCaseAnalysisSkipReason | Should -BeNullOrEmpty
    }

    It 'skips (not crashes) expected-case analysis when case generation exceeds -MaxScenarios, and reports why -- policy-level drift is still reported' {
        $oldDir = New-TestSnapshotDir
        $newDir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $oldDir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $newDir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRoleEntity))
        Write-TestEvidenceFile -Dir $newDir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @((New-TestCaPolicyEntity -Id 'p1' -Platforms @('windows', 'iOS', 'android', 'macOS', 'linux')))
        $oldProvider = New-EntraPostureEvidenceProvider -SnapshotPath $oldDir
        $newProvider = New-EntraPostureEvidenceProvider -SnapshotPath $newDir

        { Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldProvider -NewEvidenceProvider $newProvider -OldSnapshotId 'old' -NewSnapshotId 'new' -MaxScenarios 5 } | Should -Not -Throw
        $result = Compare-EntraPostureConditionalAccessDrift -OldEvidenceProvider $oldProvider -NewEvidenceProvider $newProvider -OldSnapshotId 'old' -NewSnapshotId 'new' -MaxScenarios 5
        $result.ExpectedCaseAnalysisSkipped | Should -BeTrue
        $result.ExpectedCaseAnalysisSkipReason | Should -Not -BeNullOrEmpty
        @($result.DriftEvents | Where-Object { $_.category -eq 'PolicyAdded' }).Count | Should -Be 1
    }
}
