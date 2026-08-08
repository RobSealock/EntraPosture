#Requires -Version 7.4

function ConvertTo-EntraPostureAdministrativeUnitEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph administrativeUnit object
        (GET /v1.0/directory/administrativeUnits) into a canonical Entity record.

        .DESCRIPTION
        Field allowlist per section 8.4: id, displayName, description, visibility.

        .PARAMETER RawAdministrativeUnit
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
        [System.Collections.Specialized.OrderedDictionary]$RawAdministrativeUnit,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawAdministrativeUnit.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawAdministrativeUnit['id'])) {
        throw 'ConvertTo-EntraPostureAdministrativeUnitEntity: raw administrativeUnit record has no id.'
    }

    return [ordered]@{
        entityId         = [string]$RawAdministrativeUnit['id']
        entityType       = 'AdministrativeUnit'
        tenantScope      = $TenantScope
        displayName      = if ($RawAdministrativeUnit.Contains('displayName')) { $RawAdministrativeUnit['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            description = if ($RawAdministrativeUnit.Contains('description')) { $RawAdministrativeUnit['description'] } else { $null }
            visibility  = if ($RawAdministrativeUnit.Contains('visibility')) { $RawAdministrativeUnit['visibility'] } else { $null }
        }
        redacted         = $false
    }
}
