#Requires -Version 7.4

function Get-EntraPostureAdministrativeUnitCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAdministrativeUnitCollector's permission/coverage
        requirements.

        .DESCRIPTION
        AdministrativeUnit.Read.All is Microsoft's documented least-privileged permission. No
        control depends on AdministrativeUnit evidence yet.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AdministrativeUnits' `
        -RequiredPermissions @('AdministrativeUnit.Read.All') `
        -EndpointsUsed @('/v1.0/directory/administrativeUnits') `
        -AffectedControlIds @() `
        -AffectedReportSections @('Identity')
}

function Invoke-EntraPostureAdministrativeUnitCollector {
    <#
        .SYNOPSIS
        Collects administrative units, normalized to canonical Entity records. Read-only: one
        allowlisted, paginated Graph GET call.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (AdministrativeUnit[]).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https',

        [Parameter()]
        [string]$RequestHostOverride = 'graph.microsoft.com'
    )

    $collectorVersion = (Get-EntraPostureToolVersionInfo).ToolVersion
    $collectedAt = (Get-Date).ToUniversalTime().ToString('o')

    $sendParams = @{
        RequestHost  = $RequestHostOverride
        ApiStability = 'Stable'
        AccessToken  = $AccessToken
    }
    if ($AllowlistOverride) { $sendParams['AllowlistOverride'] = $AllowlistOverride }
    if ($SchemeOverride -ne 'https') { $sendParams['SchemeOverride'] = $SchemeOverride }

    $path = '/v1.0/directory/administrativeUnits'
    $rawUnits = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawUnit in $rawUnits) {
        ConvertTo-EntraPostureAdministrativeUnitEntity -RawAdministrativeUnit $rawUnit -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
