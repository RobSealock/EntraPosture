#Requires -Version 7.4

function Get-EntraPostureAuthenticationContextCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureAuthenticationContextCollector's permission/coverage
        requirements.

        .DESCRIPTION
        AuthenticationContext.Read.All -- corrected 2026-08-06 during control design (was
        wrongly assumed Policy.Read.All by analogy; 00-permission-report-matrix.md). Feeds the
        future AUTHCTX-001/AUTHCTX-002 controls (Phase 7).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'AuthenticationContexts' `
        -RequiredPermissions @('AuthenticationContext.Read.All') `
        -EndpointsUsed @('/v1.0/identity/conditionalAccess/authenticationContextClassReferences') `
        -AffectedControlIds @('AUTHCTX-001', 'AUTHCTX-002') `
        -AffectedReportSections @('Conditional Access')
}

function Invoke-EntraPostureAuthenticationContextCollector {
    <#
        .SYNOPSIS
        Collects authentication context class references, normalized to canonical Entity
        records. Read-only: one allowlisted, paginated Graph GET call.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.

        .OUTPUTS
        Ordered dictionary: Entities (AuthenticationContextClassReference[]).
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

    $path = '/v1.0/identity/conditionalAccess/authenticationContextClassReferences'
    $rawContexts = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    $entities = foreach ($rawContext in $rawContexts) {
        ConvertTo-EntraPostureAuthenticationContextEntity -RawContext $rawContext -TenantScope $TenantScope `
            -CollectorVersion $collectorVersion -SourceEndpoint $path -CollectedAt $collectedAt
    }

    return [ordered]@{
        Entities = @($entities)
    }
}
