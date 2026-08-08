#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 5 (authenticationStrength half): Resolve-EntraPostureAuthenticationStrengthRequirement.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/ConditionalAccess/ResolveAuthenticationStrength.ps1')

    function script:New-TestAuthStrengthPolicy {
        param([string]$Id, [string]$PolicyType = 'builtIn', [string]$RequirementsSatisfied = 'mfa', [string[]]$AllowedCombinations = @())
        return [ordered]@{
            entityId = $Id; entityType = 'AuthenticationStrengthPolicy'; tenantScope = 't1'
            displayName = $Id; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
            sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{ policyType = $PolicyType; requirementsSatisfied = $RequirementsSatisfied; allowedCombinations = $AllowedCombinations }
        }
    }
}

Describe 'Resolve-EntraPostureAuthenticationStrengthRequirement' {
    It 'resolves an ID that matches a collected policy' {
        $policies = @((New-TestAuthStrengthPolicy -Id 'as-1' -RequirementsSatisfied 'mfa' -AllowedCombinations @('fido2', 'windowsHelloForBusiness')))
        $result = Resolve-EntraPostureAuthenticationStrengthRequirement -AuthenticationStrengthPolicies $policies -AuthenticationStrengthId 'as-1'

        $result.Resolved | Should -BeTrue
        @($result.AllowedCombinations) | Should -Be @('fido2', 'windowsHelloForBusiness')
        $result.RequirementsSatisfied | Should -Be 'mfa'
        $result.PolicyType | Should -Be 'builtIn'
    }

    It 'returns Resolved=$false for a null AuthenticationStrengthId (the common case -- most policies use builtInControls)' {
        $result = Resolve-EntraPostureAuthenticationStrengthRequirement -AuthenticationStrengthPolicies @() -AuthenticationStrengthId $null
        $result.Resolved | Should -BeFalse
        @($result.AllowedCombinations).Count | Should -Be 0
    }

    It 'returns Resolved=$false for an empty-string AuthenticationStrengthId' {
        $result = Resolve-EntraPostureAuthenticationStrengthRequirement -AuthenticationStrengthPolicies @() -AuthenticationStrengthId ''
        $result.Resolved | Should -BeFalse
    }

    It 'returns Resolved=$false when the ID matches no collected policy (e.g. evidence not collected, or a stale reference)' {
        $policies = @((New-TestAuthStrengthPolicy -Id 'as-1'))
        $result = Resolve-EntraPostureAuthenticationStrengthRequirement -AuthenticationStrengthPolicies $policies -AuthenticationStrengthId 'as-nonexistent'
        $result.Resolved | Should -BeFalse
        @($result.AllowedCombinations).Count | Should -Be 0
        $result.RequirementsSatisfied | Should -BeNullOrEmpty
    }

    It 'resolves a custom policy that does not satisfy MFA (requirementsSatisfied=none)' {
        $policies = @((New-TestAuthStrengthPolicy -Id 'as-weak' -PolicyType 'custom' -RequirementsSatisfied 'none' -AllowedCombinations @('password')))
        $result = Resolve-EntraPostureAuthenticationStrengthRequirement -AuthenticationStrengthPolicies $policies -AuthenticationStrengthId 'as-weak'
        $result.Resolved | Should -BeTrue
        $result.RequirementsSatisfied | Should -Be 'none'
        $result.PolicyType | Should -Be 'custom'
    }
}
