#Requires -Version 7.4

function ConvertTo-EntraPostureAzureRoleDefinitionEntity {
    <#
        .SYNOPSIS
        Normalizes one raw ARM roleDefinition object
        (GET /{scope}/providers/Microsoft.Authorization/roleDefinitions) into a canonical
        Entity record.

        .DESCRIPTION
        Field allowlist per section 8.4: id, name (the definition's GUID), properties.roleName,
        properties.type (BuiltInRole/CustomRole -- load-bearing for distinguishing tenant-authored
        custom roles from Microsoft's built-ins), properties.assignableScopes.

        .PARAMETER RawRoleDefinition
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
        [System.Collections.Specialized.OrderedDictionary]$RawRoleDefinition,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawRoleDefinition.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawRoleDefinition['id'])) {
        throw 'ConvertTo-EntraPostureAzureRoleDefinitionEntity: raw roleDefinition record has no id.'
    }
    $props = if ($RawRoleDefinition.Contains('properties')) { $RawRoleDefinition['properties'] } else { $null }

    return [ordered]@{
        entityId         = [string]$RawRoleDefinition['id']
        entityType       = 'AzureRoleDefinition'
        tenantScope      = $TenantScope
        displayName      = if ($props -and $props.Contains('roleName')) { $props['roleName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            name              = if ($RawRoleDefinition.Contains('name')) { [string]$RawRoleDefinition['name'] } else { $null }
            roleType          = if ($props -and $props.Contains('type')) { $props['type'] } else { $null }
            assignableScopes  = @(if ($props -and $props.Contains('assignableScopes')) { $props['assignableScopes'] } else { @() })
        }
        redacted         = $false
    }
}
