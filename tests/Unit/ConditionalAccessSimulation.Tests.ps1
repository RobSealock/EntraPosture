#Requires -Version 7.4
#Requires -Modules Pester

<#
    Phase 8: the deterministic CA simulation engine (WS4's "flagship" deliverable), evaluated
    against 16-ca-evaluation-semantics.md's cited rules -- one Describe block per semantic rule
    that document names, plus the per-dimension matching tests the engine's own explanation trace
    depends on.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/ConditionalAccess/DeviceFilterTokenizer.ps1',
        'src/ConditionalAccess/DeviceFilterParser.ps1',
        'src/ConditionalAccess/DeviceFilterEvaluator.ps1',
        'src/ConditionalAccess/EvaluateDeviceFilterCondition.ps1',
        'src/ConditionalAccess/ScenarioModel.ps1',
        'src/ConditionalAccess/MatchPolicy.ps1',
        'src/ConditionalAccess/EvaluateScenario.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    function script:New-TestPolicy {
        param(
            [string]$Id = 'policy-1',
            [string]$DisplayName = 'Test Policy',
            [string]$State = 'enabled',
            [string[]]$IncludeUsers = @('All'),
            [string[]]$ExcludeUsers = @(),
            [string[]]$IncludeGroups = @(),
            [string[]]$ExcludeGroups = @(),
            [string[]]$IncludeRoles = @(),
            [string[]]$ExcludeRoles = @(),
            [string[]]$IncludeGuestOrExternalUserTypes = @(),
            [string[]]$ExcludeGuestOrExternalUserTypes = @(),
            [string[]]$IncludeApplications = @('All'),
            [string[]]$ExcludeApplications = @(),
            [string[]]$ClientAppTypes = @(),
            [string[]]$IncludePlatforms = @(),
            [string[]]$ExcludePlatforms = @(),
            [string[]]$IncludeLocations = @(),
            [string[]]$ExcludeLocations = @(),
            [string[]]$SignInRiskLevels = @(),
            [string[]]$UserRiskLevels = @(),
            [string[]]$IncludeServicePrincipals = @(),
            [string[]]$ExcludeServicePrincipals = @(),
            [string[]]$ServicePrincipalRiskLevels = @(),
            [string]$Operator = 'AND',
            [string[]]$BuiltInControls = @('mfa'),
            [string]$DeviceFilterMode = $null,
            [string]$DeviceFilterRule = $null
        )
        return [ordered]@{
            entityId = $Id; entityType = 'ConditionalAccessPolicy'; tenantScope = 't1'
            displayName = $DisplayName; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
            sourceEndpoint = '/v1.0/identity/conditionalAccess/policies'; redacted = $false
            properties = [ordered]@{
                state = $State; createdDateTime = $null; modifiedDateTime = $null
                conditions = [ordered]@{
                    clientAppTypes = $ClientAppTypes; signInRiskLevels = $SignInRiskLevels; userRiskLevels = $UserRiskLevels
                    servicePrincipalRiskLevels = $ServicePrincipalRiskLevels; insiderRiskLevels = $null
                    users = [ordered]@{
                        includeUsers = $IncludeUsers; excludeUsers = $ExcludeUsers
                        includeGroups = $IncludeGroups; excludeGroups = $ExcludeGroups
                        includeRoles = $IncludeRoles; excludeRoles = $ExcludeRoles
                        includeGuestOrExternalUserTypes = $IncludeGuestOrExternalUserTypes
                        excludeGuestOrExternalUserTypes = $ExcludeGuestOrExternalUserTypes
                    }
                    applications = [ordered]@{
                        includeApplications = $IncludeApplications; excludeApplications = $ExcludeApplications
                        includeUserActions = @(); includeAuthenticationContextClassReferences = @()
                    }
                    platforms = [ordered]@{ includePlatforms = $IncludePlatforms; excludePlatforms = $ExcludePlatforms }
                    locations = [ordered]@{ includeLocations = $IncludeLocations; excludeLocations = $ExcludeLocations }
                    devices = [ordered]@{ deviceFilterMode = $DeviceFilterMode; deviceFilterRule = $DeviceFilterRule }
                    clientApplications = [ordered]@{ includeServicePrincipals = $IncludeServicePrincipals; excludeServicePrincipals = $ExcludeServicePrincipals }
                    authenticationFlowTransferMethods = $null
                }
                grantControls = [ordered]@{
                    operator = $Operator; builtInControls = $BuiltInControls
                    customAuthenticationFactors = @(); termsOfUse = @(); authenticationStrengthId = $null
                }
                sessionControls = [ordered]@{
                    signInFrequencyIsEnabled = $null; signInFrequencyValue = $null; signInFrequencyType = $null; signInFrequencyAuthenticationType = $null
                    persistentBrowserIsEnabled = $null; persistentBrowserMode = $null
                    applicationEnforcedRestrictionsIsEnabled = $null; cloudAppSecurityIsEnabled = $null; cloudAppSecurityType = $null
                    disableResilienceDefaults = $null
                }
            }
        }
    }

    function script:New-TestScenario {
        param(
            [string]$UserId = 'user-1', [string[]]$UserGroupIds = @(), [string[]]$UserRoleIds = @(), [bool]$IsGuest = $false,
            [string]$ApplicationId = 'app-1', [string]$ClientAppType = 'browser', [string]$Platform = 'windows',
            [string[]]$LocationId = @('loc-1'), [bool]$IsTrustedLocation = $false, [string]$SignInRiskLevel = 'none', [string]$UserRiskLevel = 'none',
            [bool]$IsCompliantDevice = $false, [bool]$IsHybridJoined = $false,
            [bool]$IsDeviceRegistered = $false, [bool]$IsIntuneManaged = $false,
            [System.Collections.Specialized.OrderedDictionary]$DeviceAttributes = [ordered]@{}
        )
        return New-EntraPostureConditionalAccessScenario -UserId $UserId -UserGroupIds $UserGroupIds -UserRoleIds $UserRoleIds -IsGuest $IsGuest `
            -ApplicationId $ApplicationId -ClientAppType $ClientAppType -Platform $Platform -LocationId $LocationId -IsTrustedLocation $IsTrustedLocation `
            -SignInRiskLevel $SignInRiskLevel -UserRiskLevel $UserRiskLevel -IsCompliantDevice $IsCompliantDevice -IsHybridJoined $IsHybridJoined `
            -IsDeviceRegistered $IsDeviceRegistered -IsIntuneManaged $IsIntuneManaged -DeviceAttributes $DeviceAttributes
    }

    function script:New-TestWorkloadIdentityScenario {
        param(
            [string]$ServicePrincipalId = 'sp-1', [string[]]$LocationId = @('All'), [bool]$IsTrustedLocation = $false, [string]$ServicePrincipalRiskLevel = 'none'
        )
        return New-EntraPostureConditionalAccessWorkloadIdentityScenario -ServicePrincipalId $ServicePrincipalId `
            -LocationId $LocationId -IsTrustedLocation $IsTrustedLocation -ServicePrincipalRiskLevel $ServicePrincipalRiskLevel
    }
}

Describe 'Test-EntraPostureConditionalAccessPolicyMatch: users dimension' {
    It 'matches "All" users' {
        $result = Test-EntraPostureConditionalAccessPolicyMatch -Policy (New-TestPolicy -IncludeUsers @('All')) -Scenario (New-TestScenario -UserId 'anyone')
        $result.Applies | Should -BeTrue
    }

    It 'matches a specific included user by ID' {
        $result = Test-EntraPostureConditionalAccessPolicyMatch -Policy (New-TestPolicy -IncludeUsers @('user-1')) -Scenario (New-TestScenario -UserId 'user-1')
        $result.Applies | Should -BeTrue
    }

    It 'matches via group membership' {
        $result = Test-EntraPostureConditionalAccessPolicyMatch -Policy (New-TestPolicy -IncludeUsers @() -IncludeGroups @('grp-1')) -Scenario (New-TestScenario -UserGroupIds @('grp-1', 'grp-2'))
        $result.Applies | Should -BeTrue
    }

    It 'matches via role membership' {
        $result = Test-EntraPostureConditionalAccessPolicyMatch -Policy (New-TestPolicy -IncludeUsers @() -IncludeRoles @('role-ga')) -Scenario (New-TestScenario -UserRoleIds @('role-ga'))
        $result.Applies | Should -BeTrue
    }

    It 'exclude wins even when the user also matches an include path (16-ca-evaluation-semantics.md §4)' {
        $policy = New-TestPolicy -IncludeUsers @('All') -ExcludeUsers @('break-glass-1')
        $result = Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -UserId 'break-glass-1')
        $result.Applies | Should -BeFalse
        $result.ExcludedByDimension | Should -Be 'users'
    }

    It 'exclude-by-group wins even when the user is separately included by "All"' {
        $policy = New-TestPolicy -IncludeUsers @('All') -ExcludeGroups @('grp-exempt')
        $result = Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -UserGroupIds @('grp-exempt'))
        $result.Applies | Should -BeFalse
        $result.ExcludedByDimension | Should -Be 'users'
    }

    It 'matches a guest via includeGuestOrExternalUserTypes' {
        $policy = New-TestPolicy -IncludeUsers @() -IncludeGuestOrExternalUserTypes @('b2bCollaborationGuest')
        $result = Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -IsGuest $true)
        $result.Applies | Should -BeTrue
    }

    It 'does not apply when the user matches no include path at all' {
        $policy = New-TestPolicy -IncludeUsers @('some-other-user')
        $result = Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -UserId 'user-1')
        $result.Applies | Should -BeFalse
        $result.ExcludedByDimension | Should -Be $null
    }
}

Describe 'Test-EntraPostureConditionalAccessPolicyMatch: applications, platforms, locations, clientAppTypes' {
    It 'matches "All" applications' {
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy (New-TestPolicy -IncludeApplications @('All')) -Scenario (New-TestScenario)).Applies | Should -BeTrue
    }

    It 'exclude wins for applications' {
        $policy = New-TestPolicy -IncludeApplications @('All') -ExcludeApplications @('app-1')
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -ApplicationId 'app-1')).Applies | Should -BeFalse
    }

    It 'unconfigured platforms condition matches every platform' {
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy (New-TestPolicy -IncludePlatforms @()) -Scenario (New-TestScenario -Platform 'macOS')).Applies | Should -BeTrue
    }

    It 'configured platforms condition excludes a non-matching platform' {
        $policy = New-TestPolicy -IncludePlatforms @('windows')
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -Platform 'macOS')).Applies | Should -BeFalse
    }

    It 'unconfigured locations condition matches every location' {
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy (New-TestPolicy -IncludeLocations @()) -Scenario (New-TestScenario -LocationId 'anywhere')).Applies | Should -BeTrue
    }

    It 'exclude wins for locations' {
        $policy = New-TestPolicy -IncludeLocations @('All') -ExcludeLocations @('trusted-hq')
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -LocationId 'trusted-hq')).Applies | Should -BeFalse
    }

    It 'matches when ANY of the scenario''s multiple resolved location IDs is in the include list (VNext build order item 4)' {
        $policy = New-TestPolicy -IncludeLocations @('loc-narrow')
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -LocationId @('loc-broad', 'loc-narrow'))).Applies | Should -BeTrue
    }

    It 'exclude wins if ANY of the scenario''s multiple resolved location IDs is in the exclude list' {
        $policy = New-TestPolicy -IncludeLocations @('All') -ExcludeLocations @('loc-narrow')
        $result = Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -LocationId @('loc-broad', 'loc-narrow'))
        $result.Applies | Should -BeFalse
        $result.ExcludedByDimension | Should -Be 'locations'
    }

    It 'a policy''s literal ''AllTrusted'' include resolves against the scenario''s IsTrustedLocation flag, not a literal ID match' {
        $policy = New-TestPolicy -IncludeLocations @('AllTrusted')
        $scenario = New-EntraPostureConditionalAccessScenario -UserId 'user-1' -ApplicationId 'app-1' -LocationId 'loc-trusted' -IsTrustedLocation $true
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario $scenario).Applies | Should -BeTrue
    }

    It 'a policy''s ''AllTrusted'' include does not match an untrusted scenario location' {
        $policy = New-TestPolicy -IncludeLocations @('AllTrusted')
        $scenario = New-EntraPostureConditionalAccessScenario -UserId 'user-1' -ApplicationId 'app-1' -LocationId 'loc-untrusted' -IsTrustedLocation $false
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario $scenario).Applies | Should -BeFalse
    }

    It 'a policy''s ''AllTrusted'' exclude wins against a trusted scenario location' {
        $policy = New-TestPolicy -IncludeLocations @('All') -ExcludeLocations @('AllTrusted')
        $scenario = New-EntraPostureConditionalAccessScenario -UserId 'user-1' -ApplicationId 'app-1' -LocationId 'loc-trusted' -IsTrustedLocation $true
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario $scenario).Applies | Should -BeFalse
    }

    It 'unconfigured clientAppTypes matches every client app type' {
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy (New-TestPolicy -ClientAppTypes @()) -Scenario (New-TestScenario -ClientAppType 'exchangeActiveSync')).Applies | Should -BeTrue
    }

    It 'configured clientAppTypes excludes a non-matching type' {
        $policy = New-TestPolicy -ClientAppTypes @('browser')
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -ClientAppType 'exchangeActiveSync')).Applies | Should -BeFalse
    }
}

Describe 'Test-EntraPostureConditionalAccessPolicyMatch: risk levels (§7 -- unconfigured is risk-independent)' {
    It 'unconfigured signInRiskLevels matches regardless of scenario risk' {
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy (New-TestPolicy -SignInRiskLevels @()) -Scenario (New-TestScenario -SignInRiskLevel 'high')).Applies | Should -BeTrue
    }

    It 'configured signInRiskLevels only matches a listed level' {
        $policy = New-TestPolicy -SignInRiskLevels @('high')
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -SignInRiskLevel 'low')).Applies | Should -BeFalse
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -SignInRiskLevel 'high')).Applies | Should -BeTrue
    }
}

Describe 'Test-EntraPostureConditionalAccessPolicyMatch: device filter (VNext build order item 5)' {
    It 'unconfigured device filter (mode/rule both null) matches regardless of device state' {
        $policy = New-TestPolicy
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario (New-TestScenario -IsDeviceRegistered $false)).Applies | Should -BeTrue
    }

    It 'include-mode device filter excludes a device that does not satisfy the rule' {
        $policy = New-TestPolicy -DeviceFilterMode 'include' -DeviceFilterRule 'device.trustType -eq "AzureAD"'
        $scenario = New-TestScenario -IsDeviceRegistered $true -DeviceAttributes ([ordered]@{ trustType = 'Workplace' })
        $result = Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario $scenario
        $result.Applies | Should -BeFalse
        $result.ExcludedByDimension | Should -Be 'devices'
    }

    It 'include-mode device filter matches a device that satisfies the rule' {
        $policy = New-TestPolicy -DeviceFilterMode 'include' -DeviceFilterRule 'device.trustType -eq "AzureAD"'
        $scenario = New-TestScenario -IsDeviceRegistered $true -DeviceAttributes ([ordered]@{ trustType = 'AzureAD' })
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario $scenario).Applies | Should -BeTrue
    }

    It 'exclude-mode device filter excludes a device that DOES satisfy the rule' {
        $policy = New-TestPolicy -DeviceFilterMode 'exclude' -DeviceFilterRule 'device.extensionAttribute1 -eq "SAW"'
        $scenario = New-TestScenario -IsDeviceRegistered $true -IsIntuneManaged $true -DeviceAttributes ([ordered]@{ extensionAttribute1 = 'SAW' })
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario $scenario).Applies | Should -BeFalse
    }

    It 'an unregistered device never satisfies a positive-operator device filter, per Microsoft''s own documented semantics' {
        $policy = New-TestPolicy -DeviceFilterMode 'include' -DeviceFilterRule 'device.trustType -eq "AzureAD"'
        $scenario = New-TestScenario -IsDeviceRegistered $false
        (Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario $scenario).Applies | Should -BeFalse
    }

    It 'an unsupported device-filter operator does not throw -- treated as a non-match, same as any other v1 boundary' {
        $policy = New-TestPolicy -DeviceFilterMode 'include' -DeviceFilterRule 'device.displayName -match "^Da.*"'
        $scenario = New-TestScenario -IsDeviceRegistered $true
        $result = Test-EntraPostureConditionalAccessPolicyMatch -Policy $policy -Scenario $scenario
        $result.Applies | Should -BeFalse
        $result.Reason | Should -Match 'unsupported'
    }
}

Describe 'Invoke-EntraPostureConditionalAccessScenario: combination semantics' {
    It 'never matches a disabled policy (§5)' {
        $policies = @((New-TestPolicy -Id 'p1' -State 'disabled'))
        $result = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario (New-TestScenario)
        $result.ApplicablePolicies.Count | Should -Be 0
        $result.NotApplicablePolicies[0].ExcludedByDimension | Should -Be 'state'
    }

    It 'block always wins and produces an empty RequiredControlGroups (§3)' {
        $policies = @(
            (New-TestPolicy -Id 'p-block' -BuiltInControls @('block'))
            (New-TestPolicy -Id 'p-mfa' -BuiltInControls @('mfa'))
        )
        $result = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario (New-TestScenario)
        $result.Result | Should -Be 'Blocked'
        $result.RequiredControlGroups.Count | Should -Be 0
    }

    It 'a report-only policy is applicable but contributes no RequiredControlGroups entry (§5)' {
        $policies = @((New-TestPolicy -Id 'p-report' -State 'enabledForReportingButNotEnforced' -BuiltInControls @('mfa')))
        $result = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario (New-TestScenario)
        $result.Result | Should -Be 'NotBlocked'
        $result.ApplicablePolicies.Count | Should -Be 1
        $result.ApplicablePolicies[0].IsReportOnly | Should -BeTrue
        $result.RequiredControlGroups.Count | Should -Be 0
    }

    It 'combines two applicable AND-operator policies as two separate required-control groups, not flattened (§1)' {
        $policies = @(
            (New-TestPolicy -Id 'p-mfa' -BuiltInControls @('mfa') -Operator 'AND')
            (New-TestPolicy -Id 'p-device' -BuiltInControls @('compliantDevice') -Operator 'AND')
        )
        $result = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario (New-TestScenario)
        $result.Result | Should -Be 'NotBlocked'
        $result.RequiredControlGroups.Count | Should -Be 2
        ($result.RequiredControlGroups | Where-Object { $_.PolicyId -eq 'p-mfa' }).Controls | Should -Be @('mfa')
        ($result.RequiredControlGroups | Where-Object { $_.PolicyId -eq 'p-device' }).Controls | Should -Be @('compliantDevice')
    }

    It 'preserves an OR-operator policy''s multiple controls as one group, not split into separate AND requirements (§2)' {
        $policies = @((New-TestPolicy -Id 'p-or' -BuiltInControls @('mfa', 'compliantDevice') -Operator 'OR'))
        $result = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario (New-TestScenario)
        $result.RequiredControlGroups.Count | Should -Be 1
        $result.RequiredControlGroups[0].Operator | Should -Be 'OR'
        $result.RequiredControlGroups[0].Controls | Should -Be @('mfa', 'compliantDevice')
    }

    It 'reports zero applicable and zero not-applicable as valid for an empty policy set' {
        $result = Invoke-EntraPostureConditionalAccessScenario -Policies @() -Scenario (New-TestScenario)
        $result.Result | Should -Be 'NotBlocked'
        $result.ApplicablePolicies.Count | Should -Be 0
        $result.RequiredControlGroups.Count | Should -Be 0
    }

    It 'records a specific, non-null Reason for every not-applicable policy (explanation trace, WS4 task 7)' {
        $policies = @((New-TestPolicy -Id 'p-other-app' -IncludeApplications @('some-other-app')))
        $result = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario (New-TestScenario -ApplicationId 'app-1')
        $result.NotApplicablePolicies.Count | Should -Be 1
        $result.NotApplicablePolicies[0].Reason | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch: clientApplications dimension (VNext build order item 3)' {
    It 'does not match when includeServicePrincipals is empty/absent -- targeting is opt-in, not defaulted' {
        $policy = New-TestPolicy -IncludeServicePrincipals @()
        (Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario (New-TestWorkloadIdentityScenario)).Applies | Should -BeFalse
    }

    It 'matches an explicitly included service principal' {
        $policy = New-TestPolicy -IncludeServicePrincipals @('sp-1')
        (Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario (New-TestWorkloadIdentityScenario -ServicePrincipalId 'sp-1')).Applies | Should -BeTrue
    }

    It 'does not match a service principal not in the include list' {
        $policy = New-TestPolicy -IncludeServicePrincipals @('sp-other')
        (Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario (New-TestWorkloadIdentityScenario -ServicePrincipalId 'sp-1')).Applies | Should -BeFalse
    }

    It 'matches the ServicePrincipalsInMyTenant sentinel (Microsoft''s own documented "every service principal" value)' {
        $policy = New-TestPolicy -IncludeServicePrincipals @('ServicePrincipalsInMyTenant')
        (Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario (New-TestWorkloadIdentityScenario -ServicePrincipalId 'sp-1')).Applies | Should -BeTrue
    }

    It 'exclude always wins over an explicit include' {
        $policy = New-TestPolicy -IncludeServicePrincipals @('sp-1') -ExcludeServicePrincipals @('sp-1')
        $result = Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario (New-TestWorkloadIdentityScenario -ServicePrincipalId 'sp-1')
        $result.Applies | Should -BeFalse
        $result.ExcludedByDimension | Should -Be 'clientApplications'
    }

    It 'exclude wins even under the ServicePrincipalsInMyTenant sentinel' {
        $policy = New-TestPolicy -IncludeServicePrincipals @('ServicePrincipalsInMyTenant') -ExcludeServicePrincipals @('sp-1')
        (Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario (New-TestWorkloadIdentityScenario -ServicePrincipalId 'sp-1')).Applies | Should -BeFalse
    }
}

Describe 'Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch: locations and service principal risk' {
    It 'unconfigured locations matches regardless of scenario location' {
        $policy = New-TestPolicy -IncludeServicePrincipals @('sp-1') -IncludeLocations @() -ExcludeLocations @()
        (Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario (New-TestWorkloadIdentityScenario -LocationId 'loc-x')).Applies | Should -BeTrue
    }

    It 'excluded location wins over a configured include' {
        $policy = New-TestPolicy -IncludeServicePrincipals @('sp-1') -IncludeLocations @('All') -ExcludeLocations @('loc-trusted')
        $result = Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario (New-TestWorkloadIdentityScenario -LocationId 'loc-trusted')
        $result.Applies | Should -BeFalse
        $result.ExcludedByDimension | Should -Be 'locations'
    }

    It 'a policy''s literal ''AllTrusted'' include resolves against the scenario''s IsTrustedLocation flag (VNext build order item 4)' {
        $policy = New-TestPolicy -IncludeServicePrincipals @('sp-1') -IncludeLocations @('AllTrusted')
        $scenario = New-EntraPostureConditionalAccessWorkloadIdentityScenario -ServicePrincipalId 'sp-1' -LocationId 'loc-trusted' -IsTrustedLocation $true
        (Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario $scenario).Applies | Should -BeTrue
    }

    It 'matches when ANY of the scenario''s multiple resolved location IDs is in the include list' {
        $policy = New-TestPolicy -IncludeServicePrincipals @('sp-1') -IncludeLocations @('loc-narrow')
        $scenario = New-EntraPostureConditionalAccessWorkloadIdentityScenario -ServicePrincipalId 'sp-1' -LocationId @('loc-broad', 'loc-narrow')
        (Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario $scenario).Applies | Should -BeTrue
    }

    It 'unconfigured servicePrincipalRiskLevels matches regardless of scenario risk (direct analogy to section 7)' {
        $policy = New-TestPolicy -IncludeServicePrincipals @('sp-1') -ServicePrincipalRiskLevels @()
        (Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario (New-TestWorkloadIdentityScenario -ServicePrincipalRiskLevel 'high')).Applies | Should -BeTrue
    }

    It 'configured servicePrincipalRiskLevels only matches a listed level' {
        $policy = New-TestPolicy -IncludeServicePrincipals @('sp-1') -ServicePrincipalRiskLevels @('high')
        (Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario (New-TestWorkloadIdentityScenario -ServicePrincipalRiskLevel 'low')).Applies | Should -BeFalse
        (Test-EntraPostureConditionalAccessWorkloadIdentityPolicyMatch -Policy $policy -Scenario (New-TestWorkloadIdentityScenario -ServicePrincipalRiskLevel 'high')).Applies | Should -BeTrue
    }
}

Describe 'Invoke-EntraPostureConditionalAccessScenario: dispatches on ScenarioKind (VNext build order item 3)' {
    It 'a workload-identity scenario only matches policies targeting service principals, never a user-targeting policy' {
        $policies = @((New-TestPolicy -Id 'p-user' -IncludeUsers @('All') -IncludeServicePrincipals @()))
        $result = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario (New-TestWorkloadIdentityScenario)
        $result.ApplicablePolicies.Count | Should -Be 0
        $result.NotApplicablePolicies.Count | Should -Be 1
    }

    It 'a user scenario never matches a workload-identity-targeting-only policy (no includeUsers at all)' {
        $policies = @((New-TestPolicy -Id 'p-workload' -IncludeUsers @() -IncludeServicePrincipals @('sp-1')))
        $result = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario (New-TestScenario)
        $result.ApplicablePolicies.Count | Should -Be 0
    }

    It 'blocks a workload-identity scenario end to end (block is documented as the only real-world grant control for this policy type)' {
        $policies = @((New-TestPolicy -Id 'p-workload-block' -IncludeServicePrincipals @('sp-1') -BuiltInControls @('block')))
        $result = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario (New-TestWorkloadIdentityScenario -ServicePrincipalId 'sp-1')
        $result.Result | Should -Be 'Blocked'
        $result.ApplicablePolicies.Count | Should -Be 1
    }

    It 'does not block a workload-identity scenario excluded via a location exclusion' {
        $policies = @((New-TestPolicy -Id 'p-workload-block' -IncludeServicePrincipals @('sp-1') -IncludeLocations @('All') -ExcludeLocations @('loc-trusted') -BuiltInControls @('block')))
        $result = Invoke-EntraPostureConditionalAccessScenario -Policies $policies -Scenario (New-TestWorkloadIdentityScenario -ServicePrincipalId 'sp-1' -LocationId 'loc-trusted')
        $result.Result | Should -Be 'NotBlocked'
        $result.NotApplicablePolicies.Count | Should -Be 1
    }
}
