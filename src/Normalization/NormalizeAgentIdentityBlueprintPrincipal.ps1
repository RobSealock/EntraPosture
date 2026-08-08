#Requires -Version 7.4

function ConvertTo-EntraPostureAgentIdentityBlueprintPrincipalEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph agentIdentityBlueprintPrincipal object
        (GET /v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal) into a
        canonical Entity record.

        .DESCRIPTION
        agentIdentityBlueprintPrincipal inherits servicePrincipal (confirmed directly against
        the live "List agentIdentityBlueprintPrincipal objects" Graph reference page, re-fetched
        2026-08-07): its response carries appOwnerOrganizationId, exactly the same field an
        ordinary foreign service principal's own tenant-of-origin is already keyed on elsewhere
        in Microsoft's own object model -- this is what AGT-004/005/011/012/017's "foreign"
        derivation (via an agentIdentity's own agentIdentityBlueprintId -> this blueprint
        principal's appOwnerOrganizationId) reads. Field allowlist: id, appId, displayName
        (from appDisplayName), appOwnerOrganizationId, accountEnabled.

        .PARAMETER RawBlueprintPrincipal
        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching entity.schema.json (entityType
        'AgentIdentityBlueprintPrincipal').
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawBlueprintPrincipal,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawBlueprintPrincipal.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawBlueprintPrincipal['id'])) {
        throw 'ConvertTo-EntraPostureAgentIdentityBlueprintPrincipalEntity: raw agentIdentityBlueprintPrincipal record has no id.'
    }

    return [ordered]@{
        entityId         = [string]$RawBlueprintPrincipal['id']
        entityType       = 'AgentIdentityBlueprintPrincipal'
        tenantScope      = $TenantScope
        displayName      = if ($RawBlueprintPrincipal.Contains('appDisplayName')) { $RawBlueprintPrincipal['appDisplayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            appId                  = if ($RawBlueprintPrincipal.Contains('appId')) { $RawBlueprintPrincipal['appId'] } else { $null }
            appOwnerOrganizationId = if ($RawBlueprintPrincipal.Contains('appOwnerOrganizationId')) { $RawBlueprintPrincipal['appOwnerOrganizationId'] } else { $null }
            accountEnabled         = if ($RawBlueprintPrincipal.Contains('accountEnabled')) { $RawBlueprintPrincipal['accountEnabled'] } else { $null }
        }
        redacted         = $false
    }
}
