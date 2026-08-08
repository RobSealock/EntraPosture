#Requires -Version 7.4
#Requires -Modules Pester

<#
    Contract/unit tests for src/Preflight: New-EntraPostureCollectorRequirement and
    Test-EntraPosturePreflight. Proves the coverage.schema.json-shaped record is actually
    produced correctly (schema-validated, not just spot-checked field by field) and that
    evidenceStatus derivation follows engineering plan section 7.2's conservative rule: token
    claims alone are never enough to call a collector 'Collected' -- only an explicit
    verification result is.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Validation/TestSchema.ps1')
    . (Join-Path $script:RepoRoot 'src/Preflight/CollectorRequirement.ps1')
    . (Join-Path $script:RepoRoot 'src/Preflight/CoveragePreflight.ps1')

    function script:New-EntraPostureTestRequirement {
        param(
            [string]$Name = 'TestCollector',
            [string[]]$RequiredPermissions = @('User.Read.All'),
            [string[]]$AffectedControlIds = @('CTRL-001')
        )
        New-EntraPostureCollectorRequirement -CollectorName $Name -RequiredPermissions $RequiredPermissions `
            -EndpointsUsed @('/v1.0/users') -AffectedControlIds $AffectedControlIds -AffectedReportSections @('Identity')
    }
}

Describe 'New-EntraPostureCollectorRequirement' {
    It 'builds a declaration with every supplied field' {
        $req = New-EntraPostureTestRequirement
        $req.CollectorName | Should -Be 'TestCollector'
        @($req.RequiredPermissions) | Should -Be @('User.Read.All')
        @($req.EndpointsUsed) | Should -Be @('/v1.0/users')
        @($req.AffectedControlIds) | Should -Be @('CTRL-001')
        @($req.AffectedReportSections) | Should -Be @('Identity')
    }
}

Describe 'Test-EntraPosturePreflight evidenceStatus derivation' {
    It 'is Denied when none of the required permissions are granted' {
        $req = New-EntraPostureTestRequirement -RequiredPermissions @('User.Read.All')
        $coverage = Test-EntraPosturePreflight -CollectorRequirements @($req) -GrantedPermissions @('Group.Read.All')
        $coverage.collectors[0].evidenceStatus | Should -Be 'Denied'
        $coverage.collectors[0].accessVerified | Should -BeFalse
    }

    It 'is Incomplete when only some of the required permissions are granted' {
        $req = New-EntraPostureTestRequirement -RequiredPermissions @('User.Read.All', 'Group.Read.All')
        $coverage = Test-EntraPosturePreflight -CollectorRequirements @($req) -GrantedPermissions @('User.Read.All')
        $coverage.collectors[0].evidenceStatus | Should -Be 'Incomplete'
    }

    It 'is Unavailable when every permission is granted but no verification result is supplied -- never assumed Collected' {
        $req = New-EntraPostureTestRequirement -RequiredPermissions @('User.Read.All')
        $coverage = Test-EntraPosturePreflight -CollectorRequirements @($req) -GrantedPermissions @('User.Read.All')
        $coverage.collectors[0].evidenceStatus | Should -Be 'Unavailable'
    }

    It 'is Collected only when every permission is granted AND verification explicitly confirms success' {
        $req = New-EntraPostureTestRequirement -RequiredPermissions @('User.Read.All')
        $coverage = Test-EntraPosturePreflight -CollectorRequirements @($req) -GrantedPermissions @('User.Read.All') `
            -EndpointVerificationResults @{ TestCollector = $true }
        $coverage.collectors[0].evidenceStatus | Should -Be 'Collected'
        $coverage.collectors[0].accessVerified | Should -BeTrue
    }

    It 'stays Denied even if a verification result is (incorrectly) supplied for a fully-denied collector' {
        $req = New-EntraPostureTestRequirement -RequiredPermissions @('User.Read.All')
        $coverage = Test-EntraPosturePreflight -CollectorRequirements @($req) -GrantedPermissions @() `
            -EndpointVerificationResults @{ TestCollector = $true }
        $coverage.collectors[0].evidenceStatus | Should -Be 'Denied'
    }

    It 'accepts an entirely empty granted-permissions set (zero consent granted) without throwing' {
        $req = New-EntraPostureTestRequirement
        { Test-EntraPosturePreflight -CollectorRequirements @($req) -GrantedPermissions @() } | Should -Not -Throw
    }

    It 'produces output that validates against coverage.schema.json' {
        $req1 = New-EntraPostureTestRequirement -Name 'CollectorA' -RequiredPermissions @('User.Read.All')
        $req2 = New-EntraPostureTestRequirement -Name 'CollectorB' -RequiredPermissions @('Policy.Read.All') -AffectedControlIds @('CTRL-002')
        $coverage = Test-EntraPosturePreflight -CollectorRequirements @($req1, $req2) -GrantedPermissions @('User.Read.All') `
            -EndpointVerificationResults @{ CollectorA = $true }

        $json = ConvertTo-EntraPostureCanonicalJson -InputObject $coverage
        $result = Test-EntraPostureSchema -Json $json -ContractName 'coverage'
        $result.IsValid | Should -BeTrue -Because ($result.Errors -join '; ')
    }
}

Describe 'Get-EntraPostureUnaffectedControlId' {
    It 'returns control IDs whose every dependent collector is Collected' {
        $req = New-EntraPostureTestRequirement -Name 'CollectorA' -RequiredPermissions @('User.Read.All') -AffectedControlIds @('CTRL-001')
        $coverage = Test-EntraPosturePreflight -CollectorRequirements @($req) -GrantedPermissions @('User.Read.All') `
            -EndpointVerificationResults @{ CollectorA = $true }
        @(Get-EntraPostureUnaffectedControlId -Coverage $coverage) | Should -Be @('CTRL-001')
    }

    It 'excludes a control ID if any dependent collector is not Collected' {
        $req1 = New-EntraPostureTestRequirement -Name 'CollectorA' -RequiredPermissions @('User.Read.All') -AffectedControlIds @('CTRL-001')
        $req2 = New-EntraPostureTestRequirement -Name 'CollectorB' -RequiredPermissions @('Policy.Read.All') -AffectedControlIds @('CTRL-001')
        $coverage = Test-EntraPosturePreflight -CollectorRequirements @($req1, $req2) -GrantedPermissions @('User.Read.All') `
            -EndpointVerificationResults @{ CollectorA = $true }
        @(Get-EntraPostureUnaffectedControlId -Coverage $coverage).Count | Should -Be 0
    }

    It 'returns an empty set when every collector is fully denied' {
        $req = New-EntraPostureTestRequirement -AffectedControlIds @('CTRL-001')
        $coverage = Test-EntraPosturePreflight -CollectorRequirements @($req) -GrantedPermissions @()
        @(Get-EntraPostureUnaffectedControlId -Coverage $coverage).Count | Should -Be 0
    }
}
