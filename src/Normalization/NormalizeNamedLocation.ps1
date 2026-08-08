#Requires -Version 7.4

function ConvertTo-EntraPostureNamedLocationEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph namedLocation object
        (GET /v1.0/identity/conditionalAccess/namedLocations) into a canonical Entity record.

        .DESCRIPTION
        Field shape confirmed directly against Microsoft Graph's namedLocation/ipNamedLocation/
        countryNamedLocation resource documentation (re-fetched 2026-08-07, all three pages'
        updated_at 2024-11-27 or earlier -- a stable, long-unmodified resource shape).

        Discriminated by the raw response's '@odata.type' -- '#microsoft.graph.ipNamedLocation'
        or '#microsoft.graph.countryNamedLocation' are the only two derived types Microsoft
        documents; an unrecognized value is preserved verbatim in locationType rather than
        thrown on, so a future third derived type degrades to "captured but not resolvable by
        this project's CIDR/country matching" instead of breaking collection entirely.

        Field allowlist per section 8.4, by derived type:
        - ipNamedLocation: isTrusted, ipRanges (each range's own '@odata.type' -- iPv4CidrRange
          or iPv6CidrRange -- is discarded; both derived types expose the same cidrAddress field,
          and .NET's System.Net.IPNetwork.Parse/Contains -- confirmed available on this project's
          minimum PowerShell 7.4 (.NET 8) target -- handles IPv4/IPv6 CIDR containment identically
          without needing the family distinction preserved).
        - countryNamedLocation: countriesAndRegions, includeUnknownCountriesAndRegions,
          countryLookupMethod. isTrusted is stored as $false for this derived type -- Microsoft's
          own countryNamedLocation resource documentation has no isTrusted property at all (only
          ipNamedLocation does), so this is a straightforward "field doesn't exist for this type"
          default, not a security judgment call.

        .PARAMETER RawLocation
        One element of the Graph response's 'value' array.

        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching entity.schema.json.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawLocation,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawLocation.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawLocation['id'])) {
        throw 'ConvertTo-EntraPostureNamedLocationEntity: raw namedLocation record has no id.'
    }

    $odataType = if ($RawLocation.Contains('@odata.type')) { [string]$RawLocation['@odata.type'] } else { $null }
    $locationType = switch ($odataType) {
        '#microsoft.graph.ipNamedLocation'      { 'IP' }
        '#microsoft.graph.countryNamedLocation' { 'Country' }
        default                                 { $odataType }
    }

    $ipRanges = @(if ($locationType -eq 'IP' -and $RawLocation.Contains('ipRanges')) {
        foreach ($rawRange in @($RawLocation['ipRanges'])) {
            if ($rawRange.Contains('cidrAddress')) { [string]$rawRange['cidrAddress'] }
        }
    })

    $isTrusted = if ($locationType -eq 'IP' -and $RawLocation.Contains('isTrusted')) { [bool]$RawLocation['isTrusted'] } else { $false }

    return [ordered]@{
        entityId         = [string]$RawLocation['id']
        entityType       = 'NamedLocation'
        tenantScope      = $TenantScope
        displayName      = if ($RawLocation.Contains('displayName')) { $RawLocation['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            locationType                      = $locationType
            isTrusted                         = $isTrusted
            ipRanges                          = $ipRanges
            countriesAndRegions               = @(if ($locationType -eq 'Country' -and $RawLocation.Contains('countriesAndRegions')) { $RawLocation['countriesAndRegions'] } else { @() })
            includeUnknownCountriesAndRegions = if ($locationType -eq 'Country' -and $RawLocation.Contains('includeUnknownCountriesAndRegions')) { [bool]$RawLocation['includeUnknownCountriesAndRegions'] } else { $false }
            countryLookupMethod               = if ($locationType -eq 'Country' -and $RawLocation.Contains('countryLookupMethod')) { $RawLocation['countryLookupMethod'] } else { $null }
        }
        redacted         = $false
    }
}
