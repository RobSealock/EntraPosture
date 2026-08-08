#Requires -Version 7.4
#Requires -Modules Pester

<#
    v.next build order item 11: Test-EntraPostureAccessPackagePrivilegedPolicyVettingControl
    (EM-001) and Test-EntraPostureAccessPackageExpirationEnforcementControl (EM-002). Admitted
    into v1 scope by the deviation record in 00-open-questions.md item 28. Same lightweight
    fixture-based Provider pattern as tests/Unit/Phase7Controls.Tests.ps1.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateAccessPackagePrivilegedPolicyVetting.ps1',
        'src/Controls/EvaluateAccessPackageExpirationEnforcement.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "em-controls-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestEntity {
        param([string]$EntityId, [string]$EntityType, [string]$DisplayName = $null, [System.Collections.Specialized.OrderedDictionary]$Properties)
        return [ordered]@{
            entityId = $EntityId; entityType = $EntityType; tenantScope = 't1'
            displayName = $DisplayName; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
            sourceEndpoint = 'x'; properties = $Properties; redacted = $false
        }
    }

    function script:New-PrivilegedGroup {
        param([string]$Id)
        return New-TestEntity -EntityId $Id -EntityType 'Group' -DisplayName 'Privileged Group' -Properties ([ordered]@{
            groupTypes = @(); securityEnabled = $true; mailEnabled = $false; isAssignableToRole = $true
        })
    }

    function script:New-Package {
        param([string]$Id, [string]$GroupId, [string]$OriginSystem = 'AadGroup')
        $resourceRoles = if ($GroupId) { @([ordered]@{ roleDisplayName = 'Member'; originSystem = $OriginSystem; originId = $GroupId; scopeDisplayName = 'Root' }) } else { @() }
        return New-TestEntity -EntityId $Id -EntityType 'AccessPackage' -DisplayName "Package $Id" -Properties ([ordered]@{
            description = $null; isHidden = $false; resourceRoles = $resourceRoles
        })
    }

    function script:New-Policy {
        param([string]$Id, [string]$PackageId, [bool]$IsAuto = $false, [Nullable[bool]]$ApprovalRequired = $true, [string]$AllowedTargetScope = 'specificDirectoryUsers', [string]$ExpirationType = 'afterDuration')
        $props = [ordered]@{
            accessPackageId = $PackageId; allowedTargetScope = $AllowedTargetScope; isAutoAssignment = $IsAuto
            isApprovalRequiredForAdd = $ApprovalRequired; expirationType = $ExpirationType; expirationEndDateTime = $null; expirationDuration = 'P90D'
        }
        return New-TestEntity -EntityId $Id -EntityType 'AccessPackageAssignmentPolicy' -DisplayName "Policy $Id" -Properties $props
    }

    function script:New-Assignment {
        param([string]$Id, [string]$PackageId, [string]$State = 'delivered')
        return New-TestEntity -EntityId $Id -EntityType 'AccessPackageAssignment' -Properties ([ordered]@{
            accessPackageId = $PackageId; state = $State; status = $State; expiredDateTime = $(if ($State -eq 'expired') { '2026-01-01T00:00:00Z' } else { $null })
        })
    }
}

Describe 'EM-001: Test-EntraPostureAccessPackagePrivilegedPolicyVettingControl' {
    It 'reports NotApplicable when no package has a privileged resource role' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-packages.jsonl' -Records @((New-Package -Id 'pkg-1' -GroupId $null))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessPackagePrivilegedPolicyVettingControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'EM001-NO-PRIVILEGED-RESOURCES'
    }

    It 'ignores a resource role whose group is not role-assignable and not Azure-role-bearing' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-packages.jsonl' -Records @((New-Package -Id 'pkg-1' -GroupId 'group-ordinary'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @(
            (New-TestEntity -EntityId 'group-ordinary' -EntityType 'Group' -Properties ([ordered]@{ groupTypes = @(); securityEnabled = $true; mailEnabled = $false; isAssignableToRole = $false }))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessPackagePrivilegedPolicyVettingControl -EvidenceProvider $provider
        $result[0].ReasonCode | Should -Be 'EM001-NO-PRIVILEGED-RESOURCES'
    }

    It 'Fails a privileged package with an auto-assignment policy (EM001-AUTO-ASSIGNMENT-NO-APPROVAL)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-packages.jsonl' -Records @((New-Package -Id 'pkg-1' -GroupId 'group-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @((New-PrivilegedGroup -Id 'group-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-package-assignment-policies.jsonl' -Records @(
            (New-Policy -Id 'pol-1' -PackageId 'pkg-1' -IsAuto $true -ApprovalRequired $null -AllowedTargetScope 'allDirectoryUsers')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessPackagePrivilegedPolicyVettingControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'EM001-AUTO-ASSIGNMENT-NO-APPROVAL'
        $result[0].Scope | Should -Be 'pkg-1'
    }

    It 'Fails a privileged package via a group that is Azure-role-bearing, not role-assignable (EM001-BROAD-SCOPE-NO-APPROVAL)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-packages.jsonl' -Records @((New-Package -Id 'pkg-1' -GroupId 'group-azure'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @(
            (New-TestEntity -EntityId 'group-azure' -EntityType 'Group' -Properties ([ordered]@{ groupTypes = @(); securityEnabled = $true; mailEnabled = $false; isAssignableToRole = $false }))
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/azure-role-assignments.jsonl' -Records @(
            (New-TestEntity -EntityId 'ra-1' -EntityType 'AzureRoleAssignment' -Properties ([ordered]@{ roleDefinitionId = 'rd1'; principalId = 'group-azure'; principalType = 'Group'; scope = '/subscriptions/sub-1'; createdOn = '2026-01-01T00:00:00Z' }))
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-package-assignment-policies.jsonl' -Records @(
            (New-Policy -Id 'pol-1' -PackageId 'pkg-1' -IsAuto $false -ApprovalRequired $false -AllowedTargetScope 'allExternalUsers')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessPackagePrivilegedPolicyVettingControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'EM001-BROAD-SCOPE-NO-APPROVAL'
    }

    It 'Passes a privileged package whose every policy requires approval or is narrowly scoped (EM001-ADEQUATELY-VETTED)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-packages.jsonl' -Records @((New-Package -Id 'pkg-1' -GroupId 'group-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @((New-PrivilegedGroup -Id 'group-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-package-assignment-policies.jsonl' -Records @(
            (New-Policy -Id 'pol-1' -PackageId 'pkg-1' -IsAuto $false -ApprovalRequired $true -AllowedTargetScope 'specificDirectoryUsers')
            (New-Policy -Id 'pol-2' -PackageId 'pkg-1' -IsAuto $false -ApprovalRequired $false -AllowedTargetScope 'specificDirectoryUsers')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessPackagePrivilegedPolicyVettingControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'EM001-ADEQUATELY-VETTED'
    }

    It 'ignores a non-privileged package while flagging a privileged one (only one result produced)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-packages.jsonl' -Records @(
            (New-Package -Id 'pkg-priv' -GroupId 'group-1')
            (New-Package -Id 'pkg-ordinary' -GroupId $null)
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @((New-PrivilegedGroup -Id 'group-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-package-assignment-policies.jsonl' -Records @(
            (New-Policy -Id 'pol-1' -PackageId 'pkg-priv' -IsAuto $true -ApprovalRequired $null)
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessPackagePrivilegedPolicyVettingControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Scope | Should -Be 'pkg-priv'
    }
}

Describe 'EM-002: Test-EntraPostureAccessPackageExpirationEnforcementControl' {
    It 'reports NotApplicable when no package is privileged' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-packages.jsonl' -Records @((New-Package -Id 'pkg-1' -GroupId $null))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessPackageExpirationEnforcementControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'EM002-NO-APPLICABLE-POLICIES'
    }

    It 'Fails a privileged package''s policy with noExpiration (EM002-POLICY-NO-EXPIRATION)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-packages.jsonl' -Records @((New-Package -Id 'pkg-1' -GroupId 'group-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @((New-PrivilegedGroup -Id 'group-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-package-assignment-policies.jsonl' -Records @(
            (New-Policy -Id 'pol-1' -PackageId 'pkg-1' -ExpirationType 'noExpiration')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessPackageExpirationEnforcementControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'EM002-POLICY-NO-EXPIRATION'
        $result[0].Scope | Should -Be 'pol-1'
    }

    It 'Passes a privileged package''s policy with a bounded expiration (EM002-EXPIRATION-ENFORCED)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-packages.jsonl' -Records @((New-Package -Id 'pkg-1' -GroupId 'group-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @((New-PrivilegedGroup -Id 'group-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-package-assignment-policies.jsonl' -Records @(
            (New-Policy -Id 'pol-1' -PackageId 'pkg-1' -ExpirationType 'afterDuration')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessPackageExpirationEnforcementControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'EM002-EXPIRATION-ENFORCED'
    }

    It 'Fails a privileged package''s assignment in state expired (EM002-ASSIGNMENT-PAST-EXPIRATION)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-packages.jsonl' -Records @((New-Package -Id 'pkg-1' -GroupId 'group-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @((New-PrivilegedGroup -Id 'group-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-package-assignments.jsonl' -Records @(
            (New-Assignment -Id 'asg-1' -PackageId 'pkg-1' -State 'expired')
            (New-Assignment -Id 'asg-2' -PackageId 'pkg-1' -State 'delivered')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessPackageExpirationEnforcementControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'EM002-ASSIGNMENT-PAST-EXPIRATION'
        $result[0].Scope | Should -Be 'asg-1'
    }

    It 'ignores an expired assignment under a non-privileged package' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-packages.jsonl' -Records @(
            (New-Package -Id 'pkg-priv' -GroupId 'group-1')
            (New-Package -Id 'pkg-ordinary' -GroupId $null)
        )
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-groups.jsonl' -Records @((New-PrivilegedGroup -Id 'group-1'))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-access-package-assignments.jsonl' -Records @(
            (New-Assignment -Id 'asg-ordinary' -PackageId 'pkg-ordinary' -State 'expired')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureAccessPackageExpirationEnforcementControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
    }
}
