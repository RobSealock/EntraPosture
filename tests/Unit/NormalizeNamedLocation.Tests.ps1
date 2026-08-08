#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 4: ConvertTo-EntraPostureNamedLocationEntity, field shapes confirmed
    directly against Microsoft Graph's namedLocation/ipNamedLocation/countryNamedLocation resource
    documentation (re-fetched 2026-08-07) -- see the normalizer's own DESCRIPTION for the citation
    trail and the deliberate per-derived-type field allowlist.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeNamedLocation.ps1')

    function script:ConvertTo-TestOrderedDictionary {
        param([Parameter(Mandatory)][string]$Json)
        return ConvertFrom-EntraPostureJson -Json $Json
    }
}

Describe 'ConvertTo-EntraPostureNamedLocationEntity: ipNamedLocation' {
    It 'maps isTrusted and ipRanges, discarding the per-range @odata.type discriminator' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{
  "@odata.type": "#microsoft.graph.ipNamedLocation", "id": "loc-1", "displayName": "Corp HQ",
  "createdDateTime": "2018-06-22T11:56:12Z", "modifiedDateTime": "2019-07-26T18:00:43Z",
  "isTrusted": true,
  "ipRanges": [
    { "@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": "10.0.0.0/8" },
    { "@odata.type": "#microsoft.graph.iPv6CidrRange", "cidrAddress": "2001:4898:80e8:7:d92a:7695:fda1:9d62/48" }
  ]
}
'@
        $entity = ConvertTo-EntraPostureNamedLocationEntity -RawLocation $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.entityId | Should -Be 'loc-1'
        $entity.entityType | Should -Be 'NamedLocation'
        $entity.properties.locationType | Should -Be 'IP'
        $entity.properties.isTrusted | Should -BeTrue
        @($entity.properties.ipRanges) | Should -Be @('10.0.0.0/8', '2001:4898:80e8:7:d92a:7695:fda1:9d62/48')
        @($entity.properties.countriesAndRegions).Count | Should -Be 0
    }

    It 'defaults isTrusted to false when the raw field is absent (Microsoft''s own documented default)' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{ "@odata.type": "#microsoft.graph.ipNamedLocation", "id": "loc-2", "ipRanges": [] }
'@
        $entity = ConvertTo-EntraPostureNamedLocationEntity -RawLocation $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.isTrusted | Should -BeFalse
    }
}

Describe 'ConvertTo-EntraPostureNamedLocationEntity: countryNamedLocation' {
    It 'maps countriesAndRegions/includeUnknownCountriesAndRegions/countryLookupMethod, and isTrusted is always false' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{
  "@odata.type": "#microsoft.graph.countryNamedLocation", "id": "loc-3", "displayName": "US and CA",
  "countriesAndRegions": ["US", "CA"], "includeUnknownCountriesAndRegions": true,
  "countryLookupMethod": "clientIpAddress"
}
'@
        $entity = ConvertTo-EntraPostureNamedLocationEntity -RawLocation $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.properties.locationType | Should -Be 'Country'
        @($entity.properties.countriesAndRegions) | Should -Be @('US', 'CA')
        $entity.properties.includeUnknownCountriesAndRegions | Should -BeTrue
        $entity.properties.countryLookupMethod | Should -Be 'clientIpAddress'
        $entity.properties.isTrusted | Should -BeFalse
        @($entity.properties.ipRanges).Count | Should -Be 0
    }
}

Describe 'ConvertTo-EntraPostureNamedLocationEntity: error handling' {
    It 'throws when the raw record has no id' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "@odata.type": "#microsoft.graph.ipNamedLocation" }'
        { ConvertTo-EntraPostureNamedLocationEntity -RawLocation $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z' } | Should -Throw '*no id*'
    }

    It 'preserves an unrecognized @odata.type verbatim rather than throwing' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "@odata.type": "#microsoft.graph.someFutureNamedLocation", "id": "loc-4" }'
        $entity = ConvertTo-EntraPostureNamedLocationEntity -RawLocation $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.locationType | Should -Be '#microsoft.graph.someFutureNamedLocation'
    }
}
