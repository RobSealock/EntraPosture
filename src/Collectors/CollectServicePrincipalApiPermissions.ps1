#Requires -Version 7.4

function Get-EntraPostureServicePrincipalApiPermissionsCollectorRequirement {
    <#
        .SYNOPSIS
        Declares Invoke-EntraPostureServicePrincipalApiPermissionsCollector's permission/coverage
        requirements.

        .DESCRIPTION
        Application.Read.All already covers GET /servicePrincipals/{id}/appRoleAssignments
        (confirmed live 2026-08-08 against the "List appRoleAssignments granted to a service
        principal" reference page -- the same permission every other ServicePrincipals-family
        collector in this project already requests, no new grant needed for the application-
        permission half). GET /servicePrincipals/{id}/oauth2PermissionGrants needs
        Directory.Read.All instead (confirmed live 2026-08-08 against the "List a service
        principal's oauth2PermissionGrants" reference page) -- a genuinely new permission scope
        for this project's delegated-permission half. New collector, VNext build order item 2's
        new-evidence phase (the "Extensive API Privileges" architecture-fork item, resolved
        2026-08-08 as a general service-principal-permission-risk control every foreign/internal/
        agent/managed-identity population reuses, not an agent-identity-specific one -- see
        ApiPermissionRiskList.ps1 and ExtensiveApiPrivilege.ps1's own header comments).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param ()

    return New-EntraPostureCollectorRequirement -CollectorName 'ServicePrincipalApiPermissions' `
        -RequiredPermissions @('Application.Read.All', 'Directory.Read.All') `
        -EndpointsUsed @(
            '/v1.0/servicePrincipals',
            '/v1.0/servicePrincipals/{spId}/appRoleAssignments',
            '/v1.0/servicePrincipals/{spId}/oauth2PermissionGrants'
        ) `
        -AffectedControlIds @('ENT-004', 'ENT-005', 'ENT-009', 'ENT-010', 'AGT-002', 'AGT-003', 'AGT-006', 'AGT-007', 'MAI-001') `
        -AffectedReportSections @('Applications')
}

function Invoke-EntraPostureServicePrincipalApiPermissionsFetch {
    <#
        .SYNOPSIS
        Fetches one service principal's Microsoft-Graph-scoped application and delegated API
        permission grants -- the per-principal unit of work
        Invoke-EntraPostureServicePrincipalApiPermissionsCollector's N+1 fetch dispatches
        concurrently via Invoke-EntraPostureBoundedParallel.

        .PARAMETER ServicePrincipalEntityId
        .PARAMETER GraphResourceId
        The tenant's own Microsoft Graph service principal object ID (resolved once by the
        caller from the same top-level /v1.0/servicePrincipals listing this collector already
        does), used to filter oauth2PermissionGrants to Graph-resource grants only --
        appRoleAssignments are filtered by resourceDisplayName instead, since that field is
        already present directly on each assignment record and needs no separate resolution.
        .PARAMETER AccessToken
        .PARAMETER CollectorVersion
        .PARAMETER CollectedAt
        .PARAMETER RequestHostOverride
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride

        .OUTPUTS
        Ordered dictionary: Entities (ServicePrincipalApiPermissions[1]).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [string]$ServicePrincipalEntityId,

        [Parameter()]
        [string]$GraphResourceId,

        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$CollectedAt,

        [Parameter(Mandatory)]
        [string]$RequestHostOverride,

        [Parameter()]
        [System.Collections.Specialized.OrderedDictionary[]]$AllowlistOverride,

        [Parameter()]
        [ValidateSet('https', 'http')]
        [string]$SchemeOverride = 'https'
    )

    $sendParams = @{
        RequestHost  = $RequestHostOverride
        ApiStability = 'Stable'
        AccessToken  = $AccessToken
    }
    if ($AllowlistOverride) { $sendParams['AllowlistOverride'] = $AllowlistOverride }
    if ($SchemeOverride -ne 'https') { $sendParams['SchemeOverride'] = $SchemeOverride }

    $appRoleAssignmentsPath = "/v1.0/servicePrincipals/$ServicePrincipalEntityId/appRoleAssignments"
    $rawAppRoleAssignments = Send-EntraPostureRequest @sendParams -Path $appRoleAssignmentsPath -Method GET
    $graphAppRoleAssignments = @($rawAppRoleAssignments | Where-Object { [string]$_['resourceDisplayName'] -eq 'Microsoft Graph' })

    $oauth2GrantsPath = "/v1.0/servicePrincipals/$ServicePrincipalEntityId/oauth2PermissionGrants"
    $rawOauth2Grants = Send-EntraPostureRequest @sendParams -Path $oauth2GrantsPath -Method GET
    $graphOauth2Grants = if ([string]::IsNullOrWhiteSpace($GraphResourceId)) {
        @()
    } else {
        @($rawOauth2Grants | Where-Object { [string]$_['resourceId'] -eq $GraphResourceId })
    }

    $entity = ConvertTo-EntraPostureServicePrincipalApiPermissionsEntity -ServicePrincipalEntityId $ServicePrincipalEntityId `
        -RawAppRoleAssignments $graphAppRoleAssignments -RawOauth2PermissionGrants $graphOauth2Grants `
        -TenantScope $TenantScope -CollectorVersion $CollectorVersion -SourceEndpoint $appRoleAssignmentsPath -CollectedAt $CollectedAt

    return [ordered]@{
        Entities = @($entity)
    }
}

function Invoke-EntraPostureServicePrincipalApiPermissionsCollector {
    <#
        .SYNOPSIS
        Collects every service principal's Microsoft-Graph-scoped application and delegated API
        permission grants, normalized to canonical ServicePrincipalApiPermissions Entity records.
        Read-only: one paginated Graph GET call to list every service principal, plus a
        bounded-concurrent two-call fetch per principal.

        .PARAMETER AccessToken
        .PARAMETER TenantScope
        .PARAMETER AllowlistOverride
        .PARAMETER SchemeOverride
        .PARAMETER RequestHostOverride
        Test-only, defaults to the real 'graph.microsoft.com'.
        .PARAMETER FetchConcurrency
        Bounded concurrency for the per-principal fetch (default four, matching every other N+1
        collector in this project).

        .OUTPUTS
        Ordered dictionary: Entities (ServicePrincipalApiPermissions[]).
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
        [string]$RequestHostOverride = 'graph.microsoft.com',

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$FetchConcurrency = 4
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

    $path = '/v1.0/servicePrincipals'
    $rawServicePrincipals = Send-EntraPostureRequest @sendParams -Path $path -Method GET

    # Microsoft Graph's own well-known, fixed-across-every-tenant application (client) ID --
    # resolved to this tenant's own local service principal object ID (which does vary per
    # tenant) so oauth2PermissionGrants (keyed by that local object ID, not the fixed appId) can
    # be filtered to Graph-resource grants only, the same way appRoleAssignments' own
    # resourceDisplayName field already lets that half filter itself with no resolution step.
    $graphFirstPartyAppId = '00000003-0000-0000-c000-000000000000'
    $graphServicePrincipal = $rawServicePrincipals | Where-Object { [string]$_['appId'] -eq $graphFirstPartyAppId } | Select-Object -First 1
    $graphResourceId = if ($graphServicePrincipal) { [string]$graphServicePrincipal['id'] } else { $null }

    $servicePrincipalIds = @($rawServicePrincipals | ForEach-Object { [string]$_['id'] })

    $fetchParameterSets = @(foreach ($spId in $servicePrincipalIds) {
        $parameterSet = @{
            ServicePrincipalEntityId = $spId
            GraphResourceId          = $graphResourceId
            AccessToken              = $AccessToken
            TenantScope              = $TenantScope
            CollectorVersion         = $collectorVersion
            CollectedAt              = $collectedAt
            RequestHostOverride      = $RequestHostOverride
        }
        if ($AllowlistOverride) { $parameterSet['AllowlistOverride'] = $AllowlistOverride }
        if ($SchemeOverride -ne 'https') { $parameterSet['SchemeOverride'] = $SchemeOverride }
        $parameterSet
    })

    $fetchResults = Invoke-EntraPostureBoundedParallel -CommandName 'Invoke-EntraPostureServicePrincipalApiPermissionsFetch' `
        -ParameterSets $fetchParameterSets -ThrottleLimit $FetchConcurrency

    $entities = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $fetchResults.Count; $i++) {
        $fetchResult = $fetchResults[$i]
        if (-not $fetchResult.Success) {
            throw "Invoke-EntraPostureServicePrincipalApiPermissionsCollector: fetching API permissions for service principal '$($servicePrincipalIds[$i])' failed: $($fetchResult.ErrorMessage)"
        }
        foreach ($e in @($fetchResult.Result.Entities)) { $entities.Add($e) }
    }

    return [ordered]@{
        Entities = @($entities.ToArray())
    }
}
