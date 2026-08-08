#Requires -Version 7.4

function Get-EntraPostureApplicationCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureApplicationCollector's permission/coverage requirements.

        .DESCRIPTION
        Application.Read.All is Microsoft's documented least-privileged permission for listing
        app registrations. No control depends on Application evidence yet.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'Applications' `
        -RequiredPermissions @('Application.Read.All') `
        -EndpointsUsed @('/v1.0/applications') `
        -AffectedControlIds @('APP-001') `
        -AffectedReportSections @('Applications')
}

function Invoke-EntraPostureApplicationCollector {
    <#
        .SYNOPSIS
        Collects app registrations, normalized to canonical Entity records. Read-only: one
        allowlisted, paginated Graph GET call.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (Application[]).
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

    $path = '/v1.0/applications'
    $rawApplications = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawApplication in $rawApplications) {
        ConvertTo-EntraPostureApplicationEntity -RawApplication $rawApplication -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
