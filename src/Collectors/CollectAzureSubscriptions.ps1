#Requires -Version 7.4

function Get-EntraPostureAzureSubscriptionCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAzureSubscriptionCollector's permission/coverage
        requirements.

        .DESCRIPTION
        Azure ARM 'Reader' role (not a Graph permission) at the scope being queried, per
        00-permission-report-matrix.md's Azure RBAC row. No control depends on
        AzureSubscription evidence yet -- this collector exists to discover the scopes Phase 6's
        role-assignment/role-definition collectors then query, per the engineering plan's own
        "management-group/subscription discovery" phrasing.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AzureSubscriptions' `
        -RequiredPermissions @('Microsoft.Resources/subscriptions/read') `
        -EndpointsUsed @('/subscriptions') `
        -AffectedControlIds @() `
        -AffectedReportSections @('Azure RBAC')
}

function Invoke-EntraPostureAzureSubscriptionCollector {
    <#
        .SYNOPSIS
        Discovers accessible Azure subscriptions, normalized to canonical Entity records.
        Read-only: one allowlisted, paginated ARM GET call.

        .PARAMETER AccessToken
        An Azure Resource Manager-audience access token.

        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'management.azure.com'.

        .OUTPUTS
        Ordered dictionary: Entities (AzureSubscription[]).
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

    $path = '/subscriptions'
    $rawSubscriptions = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawSubscription in $rawSubscriptions) {
        ConvertTo-EntraPostureAzureSubscriptionEntity -RawSubscription $rawSubscription -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
