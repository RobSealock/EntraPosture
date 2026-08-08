#Requires -Version 7.4

function Get-EntraPostureAzureManagementGroupCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAzureManagementGroupCollector's permission/coverage
        requirements.

        .DESCRIPTION
        Azure ARM 'Reader' role at the management-group scope. No control depends on
        AzureManagementGroup evidence yet -- this collector exists for scope discovery, per
        Phase 6's "management-group/subscription discovery" phrasing.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AzureManagementGroups' `
        -RequiredPermissions @('Microsoft.Management/managementGroups/read') `
        -EndpointsUsed @('/providers/Microsoft.Management/managementGroups') `
        -AffectedControlIds @() `
        -AffectedReportSections @('Azure RBAC')
}

function Invoke-EntraPostureAzureManagementGroupCollector {
    <#
        .SYNOPSIS
        Discovers accessible Azure management groups, normalized to canonical Entity records.
        Read-only: one allowlisted, paginated ARM GET call.

        .PARAMETER AccessToken
        An Azure Resource Manager-audience access token.

        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'management.azure.com'.

        .OUTPUTS
        Ordered dictionary: Entities (AzureManagementGroup[]).
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
        [string]$RequestHostOverride = 'management.azure.com'
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

    $path = '/providers/Microsoft.Management/managementGroups'
    $rawManagementGroups = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawManagementGroup in $rawManagementGroups) {
        ConvertTo-EntraPostureAzureManagementGroupEntity -RawManagementGroup $rawManagementGroup -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
