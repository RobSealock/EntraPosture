#Requires -Version 7.4

function ConvertTo-EntraPostureAgentUserEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph agentUser object (GET /v1.0/users/microsoft.graph.agentUser)
        into a canonical Entity record.

        .DESCRIPTION
        agentUser inherits user; identityParentId "references the object ID of the associated
        agent identity" (direct quote, agentUser resource page's own property table, re-fetched
        2026-08-07) -- a plain object-ID match against AgentIdentity.entityId, unlike
        AgentIdentity's own agentIdentityBlueprintId field (see
        ConvertTo-EntraPostureAgentIdentityEntity's DESCRIPTION for that different, appId-keyed
        case). AGT-011/012/013/014/015/016's population is derived transitively through this
        field via Get-EntraPostureAgentUserForeignMap, not a direct property on agentUser itself
        for foreign-ness. Field allowlist: id, displayName, identityParentId, accountEnabled,
        userPrincipalName.

        .PARAMETER RawAgentUser
        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching entity.schema.json (entityType 'AgentUser').
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawAgentUser,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawAgentUser.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawAgentUser['id'])) {
        throw 'ConvertTo-EntraPostureAgentUserEntity: raw agentUser record has no id.'
    }

    return [ordered]@{
        entityId         = [string]$RawAgentUser['id']
        entityType       = 'AgentUser'
        tenantScope      = $TenantScope
        displayName      = if ($RawAgentUser.Contains('displayName')) { $RawAgentUser['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            identityParentId  = if ($RawAgentUser.Contains('identityParentId')) { $RawAgentUser['identityParentId'] } else { $null }
            accountEnabled    = if ($RawAgentUser.Contains('accountEnabled')) { $RawAgentUser['accountEnabled'] } else { $null }
            userPrincipalName = if ($RawAgentUser.Contains('userPrincipalName')) { $RawAgentUser['userPrincipalName'] } else { $null }
        }
        redacted         = $false
    }
}
