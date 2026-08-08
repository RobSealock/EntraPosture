#Requires -Version 7.4

function Resolve-EntraPostureNamedLocationId {
    <#
        .SYNOPSIS
        Resolves a raw sign-in IP address or country code against collected NamedLocation
        evidence into the set of named-location IDs it actually matches, plus whether any match
        is marked trusted (VNext build order item 4).

        .DESCRIPTION
        A scenario-construction helper, not part of the match/evaluate pipeline itself: the
        caller resolves a real IP/country into location ID(s) here, then passes the result into
        New-EntraPostureConditionalAccessScenario's/...WorkloadIdentityScenario's -LocationId
        (which accepts multiple IDs precisely so more than one overlapping named location can be
        represented at once -- a real IP can fall inside more than one ipNamedLocation range
        simultaneously) and -IsTrustedLocation parameters.

        CIDR containment uses .NET's System.Net.IPNetwork.Parse/.Contains (confirmed available on
        this project's minimum PowerShell 7.4 -- .NET 8 -- target; handles IPv4 and IPv6 CIDR
        identically, and normalizes a range whose address has host bits set, e.g. the literal
        '2001:4898:80e8:7:d92a:7695:fda1:9d62/48' from Microsoft's own ipNamedLocation
        documentation example, to its true network address before matching) rather than a
        hand-rolled bitwise implementation. A malformed ipRanges entry in evidence is skipped,
        not thrown on -- one bad range shouldn't invalidate resolution against every other range.

        Country matching is a literal membership test against countriesAndRegions -- no
        includeUnknownCountriesAndRegions handling, since this function is given an already-known
        country code, not a raw IP needing geolocation (which this project does not perform).

        countryNamedLocation has no isTrusted concept at all (see
        ConvertTo-EntraPostureNamedLocationEntity's own DESCRIPTION) -- a country-code
        resolution can never contribute to IsTrustedMatch.

        .PARAMETER NamedLocations
        NamedLocation entities (from ConvertTo-EntraPostureNamedLocationEntity). Empty is
        valid -- resolves to no matches, not an error.

        .PARAMETER IpAddress
        A raw IP address (v4 or v6) to resolve against every IP-type named location's ipRanges.

        .PARAMETER CountryCode
        A raw two-letter country/region code to resolve against every Country-type named
        location's countriesAndRegions.

        .OUTPUTS
        Ordered dictionary: MatchedLocationIds (string[], every named location the input actually
        falls within -- zero, one, or many), IsTrustedMatch (bool, true if any matched location
        has isTrusted=true).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Specialized.OrderedDictionary[]]$NamedLocations,

        [Parameter(ParameterSetName = 'IpAddress', Mandatory)]
        [string]$IpAddress,

        [Parameter(ParameterSetName = 'CountryCode', Mandatory)]
        [string]$CountryCode
    )

    $matchedIds = [System.Collections.Generic.List[string]]::new()
    $anyTrusted = $false

    if ($PSCmdlet.ParameterSetName -eq 'IpAddress') {
        $parsedIp = [System.Net.IPAddress]::Parse($IpAddress)

        foreach ($location in $NamedLocations) {
            if ($location.properties.locationType -ne 'IP') { continue }

            $isMatch = $false
            foreach ($cidr in @($location.properties.ipRanges)) {
                $network = $null
                try {
                    $network = [System.Net.IPNetwork]::Parse([string]$cidr)
                } catch {
                    continue
                }
                if ($network.Contains($parsedIp)) { $isMatch = $true; break }
            }

            if ($isMatch) {
                $matchedIds.Add($location.entityId)
                if ([bool]$location.properties.isTrusted) { $anyTrusted = $true }
            }
        }
    } else {
        foreach ($location in $NamedLocations) {
            if ($location.properties.locationType -ne 'Country') { continue }
            if (@($location.properties.countriesAndRegions) -contains $CountryCode) {
                $matchedIds.Add($location.entityId)
            }
        }
    }

    return [ordered]@{
        MatchedLocationIds = @($matchedIds.ToArray())
        IsTrustedMatch      = $anyTrusted
    }
}
