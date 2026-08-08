#Requires -Version 7.4

function ConvertTo-EntraPostureServicePrincipalApiPermissionsEntity {
    <#
        .SYNOPSIS
        Normalizes one service principal's Microsoft-Graph-scoped application and delegated API
        permission grants into a canonical Entity record.

        .DESCRIPTION
        A deliberately synthesized entity, not a direct one-to-one transform of a single raw
        Graph response -- the caller (CollectServicePrincipalApiPermissions.ps1's own per-
        principal fetch) has already made two separate Graph calls (GET /servicePrincipals/{id}/
        appRoleAssignments and GET /servicePrincipals/{id}/oauth2PermissionGrants, both confirmed
        directly against their own live Graph reference pages, re-fetched 2026-08-08) and filtered
        each to Microsoft Graph as the resource only -- this project's curated dangerous-
        permission list (ApiPermissionRiskList.ps1) is Microsoft-Graph-specific, so a grant
        against a third-party or first-party non-Graph API carries no classification this project
        can make and is deliberately excluded here rather than persisted as noise.

        Field allowlist per section 8.4: applicationPermissionAppRoleIds (deduplicated appRoleId
        GUIDs from Graph-resource-scoped appRoleAssignments -- appRoleId is directly comparable
        against the curated application-permission GUID set, no name resolution needed) and
        delegatedPermissionScopes (deduplicated individual scope names, each oauth2PermissionGrant
        record's own space-delimited 'scope' string split on whitespace -- confirmed via the live
        "List a service principal's oauth2PermissionGrants" reference page that 'scope' is a
        space-delimited string of permission *names*, not GUIDs, matching the curated delegated-
        permission list's own name-keyed shape).

        .PARAMETER ServicePrincipalEntityId
        The owning service principal's own entityId -- this entity's own entityId, a 1:1
        correlation key with the ServicePrincipal/ManagedIdentity/AgentIdentity entity already
        collected for the same underlying object.

        .PARAMETER RawAppRoleAssignments
        Every element of GET /servicePrincipals/{id}/appRoleAssignments' 'value' array, already
        filtered by the caller to resourceDisplayName -eq 'Microsoft Graph'.

        .PARAMETER RawOauth2PermissionGrants
        Every element of GET /servicePrincipals/{id}/oauth2PermissionGrants' 'value' array,
        already filtered by the caller to resourceId -eq the tenant's own Microsoft Graph service
        principal object ID.

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
        [string]$ServicePrincipalEntityId,

        [Parameter()]
        [object[]]$RawAppRoleAssignments = @(),

        [Parameter()]
        [object[]]$RawOauth2PermissionGrants = @(),

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    $appRoleIds = [System.Collections.Generic.List[string]]::new()
    foreach ($assignment in @($RawAppRoleAssignments)) {
        if ($assignment.Contains('appRoleId') -and -not [string]::IsNullOrWhiteSpace([string]$assignment['appRoleId'])) {
            $appRoleIds.Add([string]$assignment['appRoleId'])
        }
    }
    $applicationPermissionAppRoleIds = @($appRoleIds | Select-Object -Unique)

    $scopes = [System.Collections.Generic.List[string]]::new()
    foreach ($grant in @($RawOauth2PermissionGrants)) {
        if ($grant.Contains('scope') -and -not [string]::IsNullOrWhiteSpace([string]$grant['scope'])) {
            foreach ($scope in ([string]$grant['scope'] -split '\s+')) {
                if (-not [string]::IsNullOrWhiteSpace($scope)) { $scopes.Add($scope) }
            }
        }
    }
    $delegatedPermissionScopes = @($scopes | Select-Object -Unique)

    return [ordered]@{
        entityId         = $ServicePrincipalEntityId
        entityType       = 'ServicePrincipalApiPermissions'
        tenantScope      = $TenantScope
        displayName      = $null
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            applicationPermissionAppRoleIds = $applicationPermissionAppRoleIds
            delegatedPermissionScopes       = $delegatedPermissionScopes
        }
        redacted         = $false
    }
}
