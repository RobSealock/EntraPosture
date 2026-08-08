#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 4: Resolve-EntraPostureNamedLocationId, exercised against
    hand-built NamedLocation entity fixtures (the normalizer's own output shape -- see
    NormalizeNamedLocation.Tests.ps1 for that half of the contract).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/ConditionalAccess/ResolveNamedLocation.ps1')

    function script:New-TestNamedLocation {
        param(
            [string]$Id, [string]$LocationType, [bool]$IsTrusted = $false,
            [string[]]$IpRanges = @(), [string[]]$CountriesAndRegions = @()
        )
        return [ordered]@{
            entityId = $Id; entityType = 'NamedLocation'; tenantScope = 't1'
            displayName = $Id; collectedAt = '2026-01-01T00:00:00Z'; collectorVersion = '0.1.0'
            sourceEndpoint = 'x'; redacted = $false
            properties = [ordered]@{
                locationType = $LocationType; isTrusted = $IsTrusted; ipRanges = $IpRanges
                countriesAndRegions = $CountriesAndRegions; includeUnknownCountriesAndRegions = $false
                countryLookupMethod = $null
            }
        }
    }
}

Describe 'Resolve-EntraPostureNamedLocationId: IP resolution' {
    It 'resolves an IPv4 address that falls inside a CIDR range' {
        $locations = @((New-TestNamedLocation -Id 'loc-1' -LocationType 'IP' -IpRanges @('10.0.0.0/8')))
        $result = Resolve-EntraPostureNamedLocationId -NamedLocations $locations -IpAddress '10.1.2.3'
        $result.MatchedLocationIds | Should -Be @('loc-1')
        $result.IsTrustedMatch | Should -BeFalse
    }

    It 'resolves an IPv6 address, normalizing a range whose address has host bits set' {
        $locations = @((New-TestNamedLocation -Id 'loc-2' -LocationType 'IP' -IpRanges @('2001:4898:80e8:7:d92a:7695:fda1:9d62/48')))
        $result = Resolve-EntraPostureNamedLocationId -NamedLocations $locations -IpAddress '2001:4898:80e8:1234::1'
        $result.MatchedLocationIds | Should -Be @('loc-2')
    }

    It 'does not resolve an IP outside every configured range' {
        $locations = @((New-TestNamedLocation -Id 'loc-1' -LocationType 'IP' -IpRanges @('10.0.0.0/8')))
        $result = Resolve-EntraPostureNamedLocationId -NamedLocations $locations -IpAddress '192.168.1.1'
        @($result.MatchedLocationIds).Count | Should -Be 0
        $result.IsTrustedMatch | Should -BeFalse
    }

    It 'resolves to multiple overlapping named locations at once' {
        $locations = @(
            (New-TestNamedLocation -Id 'loc-broad' -LocationType 'IP' -IpRanges @('10.0.0.0/8'))
            (New-TestNamedLocation -Id 'loc-narrow' -LocationType 'IP' -IpRanges @('10.1.0.0/16'))
        )
        $result = Resolve-EntraPostureNamedLocationId -NamedLocations $locations -IpAddress '10.1.2.3'
        @($result.MatchedLocationIds | Sort-Object) | Should -Be @('loc-broad', 'loc-narrow')
    }

    It 'sets IsTrustedMatch when any matched location is trusted' {
        $locations = @(
            (New-TestNamedLocation -Id 'loc-untrusted' -LocationType 'IP' -IsTrusted $false -IpRanges @('10.0.0.0/8'))
            (New-TestNamedLocation -Id 'loc-trusted' -LocationType 'IP' -IsTrusted $true -IpRanges @('10.1.0.0/16'))
        )
        $result = Resolve-EntraPostureNamedLocationId -NamedLocations $locations -IpAddress '10.1.2.3'
        $result.IsTrustedMatch | Should -BeTrue
    }

    It 'skips a malformed CIDR entry rather than throwing' {
        $locations = @((New-TestNamedLocation -Id 'loc-1' -LocationType 'IP' -IpRanges @('not-a-cidr', '10.0.0.0/8')))
        $result = Resolve-EntraPostureNamedLocationId -NamedLocations $locations -IpAddress '10.1.2.3'
        $result.MatchedLocationIds | Should -Be @('loc-1')
    }

    It 'ignores Country-type named locations entirely when resolving an IP' {
        $locations = @((New-TestNamedLocation -Id 'loc-country' -LocationType 'Country' -CountriesAndRegions @('US')))
        $result = Resolve-EntraPostureNamedLocationId -NamedLocations $locations -IpAddress '10.1.2.3'
        @($result.MatchedLocationIds).Count | Should -Be 0
    }

    It 'resolves against an empty NamedLocations collection without error' {
        $result = Resolve-EntraPostureNamedLocationId -NamedLocations @() -IpAddress '10.1.2.3'
        @($result.MatchedLocationIds).Count | Should -Be 0
        $result.IsTrustedMatch | Should -BeFalse
    }
}

Describe 'Resolve-EntraPostureNamedLocationId: country resolution' {
    It 'resolves a country code present in countriesAndRegions' {
        $locations = @((New-TestNamedLocation -Id 'loc-country' -LocationType 'Country' -CountriesAndRegions @('US', 'CA')))
        $result = Resolve-EntraPostureNamedLocationId -NamedLocations $locations -CountryCode 'CA'
        $result.MatchedLocationIds | Should -Be @('loc-country')
    }

    It 'does not resolve a country code absent from countriesAndRegions' {
        $locations = @((New-TestNamedLocation -Id 'loc-country' -LocationType 'Country' -CountriesAndRegions @('US')))
        $result = Resolve-EntraPostureNamedLocationId -NamedLocations $locations -CountryCode 'FR'
        @($result.MatchedLocationIds).Count | Should -Be 0
    }

    It 'never sets IsTrustedMatch for a country match -- countryNamedLocation has no isTrusted concept' {
        $locations = @((New-TestNamedLocation -Id 'loc-country' -LocationType 'Country' -CountriesAndRegions @('US')))
        $result = Resolve-EntraPostureNamedLocationId -NamedLocations $locations -CountryCode 'US'
        $result.IsTrustedMatch | Should -BeFalse
    }

    It 'ignores IP-type named locations entirely when resolving a country' {
        $locations = @((New-TestNamedLocation -Id 'loc-ip' -LocationType 'IP' -IpRanges @('10.0.0.0/8')))
        $result = Resolve-EntraPostureNamedLocationId -NamedLocations $locations -CountryCode 'US'
        @($result.MatchedLocationIds).Count | Should -Be 0
    }
}
