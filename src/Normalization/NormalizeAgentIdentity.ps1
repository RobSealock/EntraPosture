#Requires -Version 7.4

function ConvertTo-EntraPostureAgentIdentityEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph agentIdentity object
        (GET /v1.0/servicePrincipals/microsoft.graph.agentIdentity) into a canonical Entity
        record.

        .DESCRIPTION
        agentIdentity inherits servicePrincipal, servicePrincipalType 'ServiceIdentity'
        (confirmed directly against the live "List agentIdentity objects" Graph reference page's
        own example response, re-fetched 2026-08-07). agentIdentityBlueprintId holds **the
        blueprint's appId, not either object's own id** -- confirmed directly on the
        agentIdentity resource page's own property table ("The appId of the agent identity
        blueprint that defines the configuration for this agent identity"), re-fetched
        2026-08-07, a real, non-obvious distinction: naively joining it against
        AgentIdentityBlueprintPrincipal.entityId (object ID) would silently match nothing.
        AGT-004/005/008/009's "foreign" derivation (Get-EntraPostureAgentIdentityForeignMap)
        instead joins agentIdentityBlueprintId against
        AgentIdentityBlueprintPrincipal.properties.appId to reach that principal's own
        appOwnerOrganizationId. Field allowlist: id, displayName, agentIdentityBlueprintId,
        accountEnabled.

        .PARAMETER RawAgentIdentity
        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching entity.schema.json (entityType 'AgentIdentity').
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawAgentIdentity,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawAgentIdentity.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawAgentIdentity['id'])) {
        throw 'ConvertTo-EntraPostureAgentIdentityEntity: raw agentIdentity record has no id.'
    }

    return [ordered]@{
        entityId         = [string]$RawAgentIdentity['id']
        entityType       = 'AgentIdentity'
        tenantScope      = $TenantScope
        displayName      = if ($RawAgentIdentity.Contains('displayName')) { $RawAgentIdentity['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            agentIdentityBlueprintId = if ($RawAgentIdentity.Contains('agentIdentityBlueprintId')) { $RawAgentIdentity['agentIdentityBlueprintId'] } else { $null }
            accountEnabled           = if ($RawAgentIdentity.Contains('accountEnabled')) { $RawAgentIdentity['accountEnabled'] } else { $null }
        }
        redacted         = $false
    }
}
