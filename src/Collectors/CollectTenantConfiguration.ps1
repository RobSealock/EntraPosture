#Requires -Version 7.4

function Get-EntraPostureTenantConfigurationCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureTenantConfigurationCollector's permission/coverage
        requirements.

        .DESCRIPTION
        Organization.Read.All (also covers identitySecurityDefaultsEnforcementPolicy per
        Microsoft's documentation) is the least-privileged permission for both endpoints this
        collector calls. No control depends on this evidence yet -- MS-ENTRA-001 (Security
        Defaults status) is a confirmed v1 coverage gap, not yet a designed/built control
        (00-permission-report-matrix.md), so AffectedControlIds stays empty for now.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'TenantConfiguration' `
        -RequiredPermissions @('Organization.Read.All') `
        -EndpointsUsed @('/v1.0/organization', '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy') `
        -AffectedControlIds @() `
        -AffectedReportSections @('Tenant Configuration')
}

function Invoke-EntraPostureTenantConfigurationCollector {
    <#
        .SYNOPSIS
        Collects the tenant's organization record and Security Defaults enforcement status,
        normalized to canonical Entity records. Read-only: two allowlisted Graph GET calls.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (Organization[], SecurityDefaultsPolicy[1]).
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

    $entities = [System.Collections.Generic.List[object]]::new()

    $orgPath = '/v1.0/organization'
    $rawOrganizations = Send-EntraPostureRequest @sendParams -Path $orgPath -Method GET
    foreach ($rawOrganization in $rawOrganizations) {
        $entities.Add((ConvertTo-EntraPostureOrganizationEntity -RawOrganization $rawOrganization -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $orgPath -CollectedAt $collectedAt))
    }

    $secDefaultsPath = '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    $rawPolicies = Send-EntraPostureRequest @sendParams -Path $secDefaultsPath -Method GET
    foreach ($rawPolicy in $rawPolicies) {
        $entities.Add((ConvertTo-EntraPostureSecurityDefaultsPolicyEntity -RawPolicy $rawPolicy -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $secDefaultsPath -CollectedAt $collectedAt))
    }

    return [ordered]@{
        Entities = @($entities.ToArray())
    }
}
