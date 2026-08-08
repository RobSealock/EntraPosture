#Requires -Version 7.4

function ConvertTo-EntraPostureAgentIdentityBlueprintEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph agentIdentityBlueprint object
        (GET /v1.0/applications/microsoft.graph.agentIdentityBlueprint) into a canonical Entity
        record -- VNext build order item 13's agent-identity evidence domain, finishing the
        design-only admission 15-feature-parity-matrix.md section 11 left in place.

        .DESCRIPTION
        agentIdentityBlueprint inherits application (confirmed directly against the live
        "List agentIdentityBlueprint objects" Graph reference page, re-fetched 2026-08-07, not
        assumed from the platform overview alone): the response shape is an ordinary
        application object, so passwordCredentials -- AGT-001's own field -- is present exactly
        as it is on a regular app registration. Field allowlist: id, appId, displayName,
        passwordCredentialCount only -- the raw passwordCredentials array (which can carry key
        hints/thumbprints) is aggregated to a bare count at normalization time and never
        persisted, the same aggregate-not-raw redaction-by-construction choice AR-002's decision
        counts already made for review decisions.

        .PARAMETER RawBlueprint
        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching entity.schema.json (entityType 'AgentIdentityBlueprint').
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawBlueprint,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawBlueprint.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawBlueprint['id'])) {
        throw 'ConvertTo-EntraPostureAgentIdentityBlueprintEntity: raw agentIdentityBlueprint record has no id.'
    }

    $rawCredentials = if ($RawBlueprint.Contains('passwordCredentials')) { @($RawBlueprint['passwordCredentials']) } else { @() }
    $credentialCount = @($rawCredentials).Count

    return [ordered]@{
        entityId         = [string]$RawBlueprint['id']
        entityType       = 'AgentIdentityBlueprint'
        tenantScope      = $TenantScope
        displayName      = if ($RawBlueprint.Contains('displayName')) { $RawBlueprint['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            appId                  = if ($RawBlueprint.Contains('appId')) { $RawBlueprint['appId'] } else { $null }
            passwordCredentialCount = $credentialCount
        }
        redacted         = $false
    }
}
