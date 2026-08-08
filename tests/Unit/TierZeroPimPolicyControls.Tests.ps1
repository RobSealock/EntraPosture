#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 8: PIM-003 through PIM-009, exercised against a real evidence-file-
    based provider (same pattern as tests/Unit/AuthenticationContextControls.Tests.ps1), covering
    every reason code each control's own .psd1 declares.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/Controls/EvaluateTierZeroActivationDuration.ps1',
        'src/Controls/EvaluateTierZeroActivationJustification.ps1',
        'src/Controls/EvaluateTierZeroPermanentAssignment.ps1',
        'src/Controls/EvaluateTierZeroAssignmentJustification.ps1',
        'src/Controls/EvaluateTierZeroAssignmentMfa.ps1',
        'src/Controls/EvaluateTierZeroActivationNotification.ps1',
        'src/Controls/EvaluateTierZeroAuthContextOrApproval.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "pim-policy-controls-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path (Join-Path $dir 'evidence') -Force | Out-Null
        return $dir
    }

    function script:Write-TestEvidenceFile {
        param([string]$Dir, [string]$RelativePath, [object[]]$Records)
        $lines = @($Records | ForEach-Object { ConvertTo-EntraPostureCanonicalJson -InputObject $_ })
        [System.IO.File]::WriteAllText((Join-Path $Dir $RelativePath), (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    }

    function script:New-TestGaRole {
        return [ordered]@{
            entityId = '62e90394-69f5-4237-9190-012177145e10'; entityType = 'DirectoryRole'; tenantScope = 't1'
            displayName = 'Global Administrator'; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
            sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ description = $null; roleTemplateId = '62e90394-69f5-4237-9190-012177145e10'; activationInstanceId = 'inst-1' }
        }
    }

    function script:New-TestPolicyAssignment {
        param(
            [string]$Id = 'a1', [string]$RoleDefinitionId = '62e90394-69f5-4237-9190-012177145e10',
            [string[]]$EnabledRules = @(), [bool]$IsExpirationRequired = $true, [string]$MaximumDuration = 'PT4H',
            [bool]$ApprovalRequired = $false, [bool]$AuthContextEnabled = $false, [string]$AuthContextClaimValue = $null,
            [bool]$ActivationNotificationEnabled = $true,
            [string[]]$AdminAssignmentEnabledRules = @(), [bool]$AdminAssignmentIsExpirationRequired = $true,
            [string]$AdminAssignmentMaximumDuration = 'P180D'
        )
        return [ordered]@{
            entityId = $Id; entityType = 'RoleManagementPolicyAssignment'; tenantScope = 't1'
            displayName = $null; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
            sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                roleDefinitionId = $RoleDefinitionId
                enabledRules = $EnabledRules; isExpirationRequired = $IsExpirationRequired; maximumDuration = $MaximumDuration
                approvalRequired = $ApprovalRequired
                authenticationContextEnabled = $AuthContextEnabled; authenticationContextClaimValue = $AuthContextClaimValue
                activationNotificationEnabled = $ActivationNotificationEnabled
                adminAssignmentEnabledRules = $AdminAssignmentEnabledRules
                adminAssignmentIsExpirationRequired = $AdminAssignmentIsExpirationRequired
                adminAssignmentMaximumDuration = $AdminAssignmentMaximumDuration
            }
        }
    }

    function script:New-TestProvider {
        param([System.Collections.Specialized.OrderedDictionary]$PolicyAssignment, [bool]$IncludeRole = $true)
        $dir = New-TestSnapshotDir
        if ($IncludeRole) {
            Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRole))
        }
        if ($PolicyAssignment) {
            Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-role-management-policy-assignments.jsonl' -Records @($PolicyAssignment)
        }
        return New-EntraPostureEvidenceProvider -SnapshotPath $dir
    }
}

Describe 'PIM-003: Test-EntraPostureTierZeroActivationDurationControl' {
    It 'Fails when maximumDuration exceeds 4 hours' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -MaximumDuration 'PT8H')
        $result = Test-EntraPostureTierZeroActivationDurationControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'PIM-003-DURATION-EXCEEDS-THRESHOLD'
    }

    It 'Passes when maximumDuration is exactly 4 hours' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -MaximumDuration 'PT4H')
        $result = Test-EntraPostureTierZeroActivationDurationControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'PIM-003-DURATION-WITHIN-THRESHOLD'
    }

    It 'Passes when maximumDuration is under 4 hours' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -MaximumDuration 'PT1H')
        $result = Test-EntraPostureTierZeroActivationDurationControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
    }

    It 'reports tenant-scoped NotApplicable when no Tier-0 role exists' {
        $provider = New-TestProvider -PolicyAssignment $null -IncludeRole $false
        $result = Test-EntraPostureTierZeroActivationDurationControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'PIM-003-NO-TIER-ZERO-ROLES-ACTIVATED'
    }

    It 'skips a Tier-0 role with no corresponding RoleManagementPolicyAssignment (no result, not a Fail)' {
        $provider = New-TestProvider -PolicyAssignment $null -IncludeRole $true
        $result = Test-EntraPostureTierZeroActivationDurationControl -EvidenceProvider $provider
        @($result).Count | Should -Be 0
    }
}

Describe 'PIM-004: Test-EntraPostureTierZeroActivationJustificationControl' {
    It 'Fails when Justification is not in enabledRules' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -EnabledRules @('MultiFactorAuthentication'))
        $result = Test-EntraPostureTierZeroActivationJustificationControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'PIM-004-JUSTIFICATION-NOT-REQUIRED'
    }

    It 'Passes when Justification is in enabledRules' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -EnabledRules @('Justification'))
        $result = Test-EntraPostureTierZeroActivationJustificationControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'PIM-004-JUSTIFICATION-REQUIRED'
    }
}

Describe 'PIM-005: Test-EntraPostureTierZeroPermanentAssignmentControl' {
    It 'Fails when adminAssignmentIsExpirationRequired is false (permanent assignment allowed)' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -AdminAssignmentIsExpirationRequired $false)
        $result = Test-EntraPostureTierZeroPermanentAssignmentControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'PIM-005-PERMANENT-ASSIGNMENT-ALLOWED'
    }

    It 'Passes when adminAssignmentIsExpirationRequired is true' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -AdminAssignmentIsExpirationRequired $true)
        $result = Test-EntraPostureTierZeroPermanentAssignmentControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'PIM-005-EXPIRATION-REQUIRED'
    }

    It 'is independent of the EndUser/Assignment expiration field PIM-003 reads (genuinely different rule)' {
        # EndUser/Assignment expiration required (PIM-003 would Pass) but Admin/Assignment
        # expiration NOT required (PIM-005 must still Fail) -- proves the two fields are read
        # independently, not accidentally aliased to the same underlying value.
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -IsExpirationRequired $true -AdminAssignmentIsExpirationRequired $false)
        $result = Test-EntraPostureTierZeroPermanentAssignmentControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
    }
}

Describe 'PIM-006: Test-EntraPostureTierZeroAssignmentJustificationControl' {
    It 'Fails when Justification is not in adminAssignmentEnabledRules' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -EnabledRules @('Justification') -AdminAssignmentEnabledRules @())
        $result = Test-EntraPostureTierZeroAssignmentJustificationControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'PIM-006-JUSTIFICATION-NOT-REQUIRED'
    }

    It 'Passes when Justification is in adminAssignmentEnabledRules (independent of EndUser/Assignment enabledRules)' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -EnabledRules @() -AdminAssignmentEnabledRules @('Justification'))
        $result = Test-EntraPostureTierZeroAssignmentJustificationControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'PIM-006-JUSTIFICATION-REQUIRED'
    }
}

Describe 'PIM-007: Test-EntraPostureTierZeroAssignmentMfaControl' {
    It 'Fails when MultiFactorAuthentication is not in adminAssignmentEnabledRules' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -AdminAssignmentEnabledRules @('Justification'))
        $result = Test-EntraPostureTierZeroAssignmentMfaControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'PIM-007-MFA-NOT-REQUIRED'
    }

    It 'Passes when MultiFactorAuthentication is in adminAssignmentEnabledRules' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -AdminAssignmentEnabledRules @('MultiFactorAuthentication', 'Justification'))
        $result = Test-EntraPostureTierZeroAssignmentMfaControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'PIM-007-MFA-REQUIRED'
    }
}

Describe 'PIM-008: Test-EntraPostureTierZeroActivationNotificationControl' {
    It 'Fails when activationNotificationEnabled is false' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -ActivationNotificationEnabled $false)
        $result = Test-EntraPostureTierZeroActivationNotificationControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'PIM-008-NOTIFICATIONS-DISABLED'
    }

    It 'Passes when activationNotificationEnabled is true' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -ActivationNotificationEnabled $true)
        $result = Test-EntraPostureTierZeroActivationNotificationControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'PIM-008-NOTIFICATIONS-ENABLED'
    }
}

Describe 'PIM-009: Test-EntraPostureTierZeroAuthContextOrApprovalControl' {
    It 'Fails when neither authentication context nor approval is configured' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -AuthContextEnabled $false -ApprovalRequired $false)
        $result = Test-EntraPostureTierZeroAuthContextOrApprovalControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Fail'
        $result[0].ReasonCode | Should -Be 'PIM-009-NEITHER-CONFIGURED'
    }

    It 'Passes when only authentication context is configured' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -AuthContextEnabled $true -AuthContextClaimValue 'c1' -ApprovalRequired $false)
        $result = Test-EntraPostureTierZeroAuthContextOrApprovalControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
        $result[0].ReasonCode | Should -Be 'PIM-009-AT-LEAST-ONE-CONFIGURED'
    }

    It 'Passes when only approval is configured' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -AuthContextEnabled $false -ApprovalRequired $true)
        $result = Test-EntraPostureTierZeroAuthContextOrApprovalControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
    }

    It 'Passes when both authentication context and approval are configured' {
        $provider = New-TestProvider -PolicyAssignment (New-TestPolicyAssignment -AuthContextEnabled $true -AuthContextClaimValue 'c1' -ApprovalRequired $true)
        $result = Test-EntraPostureTierZeroAuthContextOrApprovalControl -EvidenceProvider $provider
        $result[0].Status | Should -Be 'Pass'
    }
}
