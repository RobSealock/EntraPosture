#Requires -Version 7.4
#Requires -Modules Pester

<#
    Phase 8: CA-001's evaluator, built on top of the CA simulation engine
    (tests/Unit/ConditionalAccessSimulation.Tests.ps1 already covers the engine's own semantics
    directly -- this file covers the control's own scenario-grid/coverage-judgment logic on top
    of it, using the evidence-provider fixture pattern established in Phase 7's control tests).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1',
        'src/Validation/StrictJson.ps1',
        'src/Evidence/EvidenceFileRegistry.ps1', 'src/Evidence/EvidenceProvider.ps1',
        'src/ConditionalAccess/ScenarioModel.ps1',
        'src/ConditionalAccess/MatchPolicy.ps1',
        'src/ConditionalAccess/EvaluateScenario.ps1',
        'src/ConditionalAccess/GenerateCombinatorialScenarios.ps1',
        'src/ConditionalAccess/ResolveAuthenticationStrength.ps1',
        'src/Controls/EvaluateConditionalAccessAdminCoverage.ps1',
        'src/Controls/EvaluateConditionalAccessCombinatorialCoverage.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestSnapshotDir {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "phase8-controls-test-$([guid]::NewGuid())"
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
            entityId = 'ga-role'; entityType = 'DirectoryRole'; tenantScope = 't1'; displayName = 'Global Administrator'
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; properties = [ordered]@{}; redacted = $false
        }
    }

    function script:New-TestCaPolicy {
        param(
            [string]$Id, [string]$State = 'enabled', [string[]]$IncludeRoles = @(), [string[]]$IncludeUsers = @('All'),
            [string[]]$Platforms = @(), [string[]]$ClientAppTypes = @(), [string[]]$BuiltInControls = @('mfa'), [string]$Operator = 'AND'
        )
        return [ordered]@{
            entityId = $Id; entityType = 'ConditionalAccessPolicy'; tenantScope = 't1'; displayName = $Id
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                state = $State; createdDateTime = $null; modifiedDateTime = $null
                conditions = [ordered]@{
                    clientAppTypes = $ClientAppTypes; signInRiskLevels = @(); userRiskLevels = @(); servicePrincipalRiskLevels = @(); insiderRiskLevels = $null
                    users = [ordered]@{ includeUsers = $IncludeUsers; excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = $IncludeRoles; excludeRoles = @(); includeGuestOrExternalUserTypes = @(); excludeGuestOrExternalUserTypes = @() }
                    applications = [ordered]@{ includeApplications = @('All'); excludeApplications = @(); includeUserActions = @(); includeAuthenticationContextClassReferences = @() }
                    platforms = [ordered]@{ includePlatforms = $Platforms; excludePlatforms = @() }
                    locations = [ordered]@{ includeLocations = @(); excludeLocations = @() }
                    devices = [ordered]@{ deviceFilterMode = $null; deviceFilterRule = $null }
                    clientApplications = [ordered]@{ includeServicePrincipals = @(); excludeServicePrincipals = @() }
                    authenticationFlowTransferMethods = $null
                }
                grantControls = [ordered]@{ operator = $Operator; builtInControls = $BuiltInControls; customAuthenticationFactors = @(); termsOfUse = @(); authenticationStrengthId = $null }
                sessionControls = [ordered]@{
                    signInFrequencyIsEnabled = $null; signInFrequencyValue = $null; signInFrequencyType = $null; signInFrequencyAuthenticationType = $null
                    persistentBrowserIsEnabled = $null; persistentBrowserMode = $null; applicationEnforcedRestrictionsIsEnabled = $null
                    cloudAppSecurityIsEnabled = $null; cloudAppSecurityType = $null; disableResilienceDefaults = $null
                }
            }
        }
    }
}

Describe 'CA-001: Test-EntraPostureConditionalAccessAdminCoverageControl' {
    It 'reports NotApplicable when no Global Administrator role exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessAdminCoverageControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'CA-001-NO-GA-ROLE-ACTIVATED'
    }

    It 'fails all 16 scenarios when the GA role exists but no CA policy covers it at all' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRole))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessAdminCoverageControl -EvidenceProvider $provider
        $result.Count | Should -Be 16
        (@($result | Where-Object { $_.Status -eq 'Fail' })).Count | Should -Be 16
        $result[0].ReasonCode | Should -Be 'CA-001-UNCOVERED-SCENARIO'
    }

    It 'passes all 16 scenarios when a broad policy requires MFA for All users, All platforms, All client app types' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRole))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'broad-mfa' -IncludeUsers @('All') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessAdminCoverageControl -EvidenceProvider $provider
        $result.Count | Should -Be 16
        (@($result | Where-Object { $_.Status -eq 'Pass' })).Count | Should -Be 16
    }

    It 'leaves exactly the uncovered platform''s 4 scenarios failing when a policy only covers 3 of 4 platforms' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRole))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'partial-platform-mfa' -IncludeUsers @('All') -Platforms @('windows', 'iOS', 'macOS') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessAdminCoverageControl -EvidenceProvider $provider

        $failed = @($result | Where-Object { $_.Status -eq 'Fail' })
        $failed.Count | Should -Be 4
        ($failed.Scope | Sort-Object) | Should -Be @('android::browser', 'android::exchangeActiveSync', 'android::mobileAppsAndDesktopClients', 'android::other')
    }

    It 'a report-only policy alone does not achieve coverage (all scenarios still fail)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRole))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'report-only-mfa' -State 'enabledForReportingButNotEnforced' -IncludeUsers @('All') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessAdminCoverageControl -EvidenceProvider $provider
        (@($result | Where-Object { $_.Status -eq 'Fail' })).Count | Should -Be 16
    }

    It 'a block policy counts as coverage (blocked sign-in is not an uncovered gap)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRole))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'block-legacy' -IncludeUsers @('All') -ClientAppTypes @('exchangeActiveSync') -BuiltInControls @('block'))
            (New-TestCaPolicy -Id 'mfa-everything-else' -IncludeUsers @('All') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessAdminCoverageControl -EvidenceProvider $provider
        (@($result | Where-Object { $_.Status -eq 'Pass' })).Count | Should -Be 16
    }
}

Describe 'CA-002: Test-EntraPostureConditionalAccessCombinatorialCoverageControl' {
    BeforeAll {
        function script:New-TestTierZeroRole {
            param([string]$Id, [string]$DisplayName)
            return [ordered]@{
                entityId = $Id; entityType = 'DirectoryRole'; tenantScope = 't1'; displayName = $DisplayName
                collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; properties = [ordered]@{}; redacted = $false
            }
        }

        function script:New-TestAuthStrengthPolicy {
            param([string]$Id, [string]$RequirementsSatisfied = 'mfa')
            return [ordered]@{
                entityId = $Id; entityType = 'AuthenticationStrengthPolicy'; tenantScope = 't1'; displayName = $Id
                collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
                properties = [ordered]@{ policyType = 'custom'; requirementsSatisfied = $RequirementsSatisfied; allowedCombinations = @('windowsHelloForBusiness') }
            }
        }
    }

    It 'reports NotApplicable when no curated Tier-0 role exists' {
        $dir = New-TestSnapshotDir
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessCombinatorialCoverageControl -EvidenceProvider $provider
        $result.Count | Should -Be 1
        $result[0].Status | Should -Be 'NotApplicable'
        $result[0].ReasonCode | Should -Be 'CA-002-NO-TIER-ZERO-ROLE-ACTIVATED'
    }

    It 'fails the baseline scenario set (2, no CA policies collected) when the GA role exists but no policy covers it' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRole))
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessCombinatorialCoverageControl -EvidenceProvider $provider
        $result.Count | Should -Be 2
        (@($result | Where-Object { $_.Status -eq 'Fail' })).Count | Should -Be 2
        $result[0].ReasonCode | Should -Be 'CA-002-UNCOVERED-SCENARIO'
    }

    It 'passes every generated scenario when a broad MFA policy covers all users' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRole))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'broad-mfa' -IncludeUsers @('All') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessCombinatorialCoverageControl -EvidenceProvider $provider
        $result.Count | Should -Be 2
        (@($result | Where-Object { $_.Status -eq 'Pass' })).Count | Should -Be 2
    }

    It 'evaluates every curated Tier-0 role present, not just Global Administrator' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @(
            (New-TestGaRole)
            (New-TestTierZeroRole -Id 'pra-role' -DisplayName 'Privileged Role Administrator')
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessCombinatorialCoverageControl -EvidenceProvider $provider
        # 2 roles x baseline 2 scenarios each = 4
        $result.Count | Should -Be 4
        ($result.Scope | ForEach-Object { $_.Split('::')[0] } | Select-Object -Unique | Sort-Object) | Should -Be @('ga-role', 'pra-role')
    }

    It 'counts a policy requiring a satisfying authenticationStrength as coverage, not just a literal mfa control (the CA-001 gap this control closes)' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRole))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-strength-policies.jsonl' -Records @(
            (New-TestAuthStrengthPolicy -Id 'strength-1' -RequirementsSatisfied 'mfa')
        )
        $policy = New-TestCaPolicy -Id 'strength-policy' -IncludeUsers @('All') -BuiltInControls @()
        $policy.properties.grantControls.authenticationStrengthId = 'strength-1'
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @($policy)
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessCombinatorialCoverageControl -EvidenceProvider $provider
        (@($result | Where-Object { $_.Status -eq 'Pass' })).Count | Should -Be $result.Count
    }

    It 'does not count an authenticationStrength whose requirementsSatisfied is not mfa as coverage' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRole))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-authentication-strength-policies.jsonl' -Records @(
            (New-TestAuthStrengthPolicy -Id 'strength-2' -RequirementsSatisfied 'none')
        )
        $policy = New-TestCaPolicy -Id 'weak-strength-policy' -IncludeUsers @('All') -BuiltInControls @()
        $policy.properties.grantControls.authenticationStrengthId = 'strength-2'
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @($policy)
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessCombinatorialCoverageControl -EvidenceProvider $provider
        (@($result | Where-Object { $_.Status -eq 'Fail' })).Count | Should -Be $result.Count
    }

    It 'expands the scenario count when a policy references a narrower platform/risk condition' {
        $dir = New-TestSnapshotDir
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-roles.jsonl' -Records @((New-TestGaRole))
        Write-TestEvidenceFile -Dir $dir -RelativePath 'evidence/entra-conditional-access.jsonl' -Records @(
            (New-TestCaPolicy -Id 'windows-only-mfa' -IncludeUsers @('All') -Platforms @('windows') -BuiltInControls @('mfa'))
        )
        $provider = New-EntraPostureEvidenceProvider -SnapshotPath $dir
        $result = Test-EntraPostureConditionalAccessCombinatorialCoverageControl -EvidenceProvider $provider
        # platforms: all, windows (2) x clientAppTypes: all (1) x locations (2) x signInRisk: none (1) x userRisk: none (1) = 4
        $result.Count | Should -Be 4
    }
}
