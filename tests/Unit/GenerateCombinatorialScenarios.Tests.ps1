#Requires -Version 7.4
#Requires -Modules Pester

<#
    v.next build order item 12: Get-EntraPostureConditionalAccessCombinatorialScenario, the
    policy-induced equivalence-partitioning case generator behind CA-002. Tests the dimension
    extraction and -MaxScenarios safety bound directly, independent of the evaluator built on top
    of it (tests/Unit/Phase8Controls.Tests.ps1 covers CA-002's own coverage-judgment logic).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/ConditionalAccess/ScenarioModel.ps1',
        'src/ConditionalAccess/GenerateCombinatorialScenarios.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestCaPolicyForGenerator {
        param([string[]]$Platforms = @(), [string[]]$ClientAppTypes = @(), [string[]]$SignInRiskLevels = @(), [string[]]$UserRiskLevels = @())
        return [ordered]@{
            entityId = 'p1'; entityType = 'ConditionalAccessPolicy'; tenantScope = 't1'; displayName = 'p1'
            collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                state = 'enabled'
                conditions = [ordered]@{
                    clientAppTypes = $ClientAppTypes; signInRiskLevels = $SignInRiskLevels; userRiskLevels = $UserRiskLevels
                    platforms = [ordered]@{ includePlatforms = $Platforms; excludePlatforms = @() }
                }
            }
        }
    }

    function script:New-TestRoleForGenerator {
        param([string]$Id)
        return [ordered]@{ entityId = $Id; entityType = 'DirectoryRole'; tenantScope = 't1'; displayName = $Id; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'; sourceEndpoint = 'x'; properties = [ordered]@{}; redacted = $false }
    }
}

Describe 'Get-EntraPostureConditionalAccessCombinatorialScenario' {
    It 'generates exactly the baseline set (2 locations only) for one role and zero policies' {
        $results = Get-EntraPostureConditionalAccessCombinatorialScenario -Policies @() -RoleEntities @((New-TestRoleForGenerator -Id 'r1'))
        # 1 role x 1 platform('all') x 1 clientAppType('all') x 2 locations x 1 signInRisk('none') x 1 userRisk('none')
        $results.Count | Should -Be 2
        ($results.Scenario.Platform | Select-Object -Unique) | Should -Be @('all')
        ($results.Scenario.IsTrustedLocation | Sort-Object -Unique) | Should -Be @($false, $true)
    }

    It 'expands the platform/clientAppType/risk dimensions to include every value a policy references' {
        $policy = New-TestCaPolicyForGenerator -Platforms @('windows', 'iOS') -ClientAppTypes @('browser') -SignInRiskLevels @('high') -UserRiskLevels @()
        $results = Get-EntraPostureConditionalAccessCombinatorialScenario -Policies @($policy) -RoleEntities @((New-TestRoleForGenerator -Id 'r1'))
        # platforms: all, windows, iOS (3); clientAppTypes: all, browser (2); locations: 2; signInRisk: none, high (2); userRisk: none (1)
        $results.Count | Should -Be (3 * 2 * 2 * 2 * 1)
        ($results.Scenario.Platform | Select-Object -Unique | Sort-Object) | Should -Be @('all', 'iOS', 'windows' | Sort-Object)
        ($results.Scenario.SignInRiskLevel | Select-Object -Unique | Sort-Object) | Should -Be @('high', 'none' | Sort-Object)
    }

    It 'skips a raw policy-condition value outside the scenario constructor''s own ValidateSet, without throwing' {
        $policy = New-TestCaPolicyForGenerator -Platforms @('windows', 'someFuturePlatformNotYetSupported')
        { Get-EntraPostureConditionalAccessCombinatorialScenario -Policies @($policy) -RoleEntities @((New-TestRoleForGenerator -Id 'r1')) } | Should -Not -Throw
        $results = Get-EntraPostureConditionalAccessCombinatorialScenario -Policies @($policy) -RoleEntities @((New-TestRoleForGenerator -Id 'r1'))
        ($results.Scenario.Platform | Select-Object -Unique) | Should -Not -Contain 'someFuturePlatformNotYetSupported'
    }

    It 'multiplies correctly across multiple roles' {
        $results = Get-EntraPostureConditionalAccessCombinatorialScenario -Policies @() -RoleEntities @((New-TestRoleForGenerator -Id 'r1'), (New-TestRoleForGenerator -Id 'r2'), (New-TestRoleForGenerator -Id 'r3'))
        $results.Count | Should -Be 6
        ($results.RoleEntity.entityId | Select-Object -Unique | Sort-Object) | Should -Be @('r1', 'r2', 'r3')
    }

    It 'throws (not silently truncates) when the computed count exceeds -MaxScenarios' {
        $policy = New-TestCaPolicyForGenerator -Platforms @('windows', 'iOS', 'android', 'macOS', 'linux')
        { Get-EntraPostureConditionalAccessCombinatorialScenario -Policies @($policy) -RoleEntities @((New-TestRoleForGenerator -Id 'r1')) -MaxScenarios 5 } | Should -Throw '*exceeds*'
    }

    It 'returns an empty array (not an error) when RoleEntities is empty' {
        $results = Get-EntraPostureConditionalAccessCombinatorialScenario -Policies @() -RoleEntities @()
        @($results).Count | Should -Be 0
    }
}
