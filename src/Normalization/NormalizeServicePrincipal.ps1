#Requires -Version 7.4

function ConvertTo-EntraPostureServicePrincipalEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph servicePrincipal object (GET /v1.0/servicePrincipals) into a
        canonical Entity record -- entityType is 'ManagedIdentity' rather than
        'ServicePrincipal' when servicePrincipalType says so.

        .DESCRIPTION
        Managed identities and ordinary service principals (enterprise apps) come from the same
        Graph endpoint and object family, distinguished only by the 'servicePrincipalType'
        field ('ManagedIdentity' vs. 'Application'/'SocialIdp'/etc.) -- entity.schema.json
        already carries both as distinct entityType enum values (from Phase 3), so this
        normalizer branches on that field rather than the collector needing two separate
        endpoints or two separate normalizer functions for what is, on the wire, identical
        data.

        Field allowlist per section 8.4: id, appId, displayName, servicePrincipalType,
        accountEnabled.

        .PARAMETER RawServicePrincipal
        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching entity.schema.json (entityType 'ServicePrincipal' or
        'ManagedIdentity').
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawServicePrincipal,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawServicePrincipal.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawServicePrincipal['id'])) {
        throw 'ConvertTo-EntraPostureServicePrincipalEntity: raw servicePrincipal record has no id.'
    }

    $spType = if ($RawServicePrincipal.Contains('servicePrincipalType')) { [string]$RawServicePrincipal['servicePrincipalType'] } else { $null }
    $entityType = if ($spType -eq 'ManagedIdentity') { 'ManagedIdentity' } else { 'ServicePrincipal' }

    return [ordered]@{
        entityId         = [string]$RawServicePrincipal['id']
        entityType       = $entityType
        tenantScope      = $TenantScope
        displayName      = if ($RawServicePrincipal.Contains('displayName')) { $RawServicePrincipal['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            appId                 = if ($RawServicePrincipal.Contains('appId')) { $RawServicePrincipal['appId'] } else { $null }
            servicePrincipalType  = $spType
            accountEnabled        = if ($RawServicePrincipal.Contains('accountEnabled')) { $RawServicePrincipal['accountEnabled'] } else { $null }
        }
        redacted         = $false
    }
}
