#Requires -Version 7.4

function Get-EntraPostureAzureRoleDefinitionCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAzureRoleDefinitionCollector's permission/coverage
        requirements.

        .DESCRIPTION
        Azure ARM 'Reader' role at the scope being queried. No control depends on
        AzureRoleDefinition evidence yet.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AzureRoleDefinitions' `
        -RequiredPermissions @('Microsoft.Authorization/roleDefinitions/read') `
        -EndpointsUsed @('/{scope}/providers/Microsoft.Authorization/roleDefinitions') `
        -AffectedControlIds @() `
        -AffectedReportSections @('Azure RBAC')
}

function Invoke-EntraPostureAzureRoleDefinitionCollector {
    <#
        .SYNOPSIS
        Collects Azure RBAC role definitions visible at one ARM scope, normalized to canonical
        Entity records. Read-only: one allowlisted ARM GET call.

        .PARAMETER AccessToken
        .PARAMETER Scope
        ARM scope path, e.g. '/subscriptions/{id}' or
        '/providers/Microsoft.Management/managementGroups/{id}'.

        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'management.azure.com'.

        .OUTPUTS
        Ordered dictionary: Entities (AzureRoleDefinition[]).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$Scope,

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

    $path = "$Scope/providers/Microsoft.Authorization/roleDefinitions"
    $rawRoleDefinitions = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawRoleDefinition in $rawRoleDefinitions) {
        ConvertTo-EntraPostureAzureRoleDefinitionEntity -RawRoleDefinition $rawRoleDefinition -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
