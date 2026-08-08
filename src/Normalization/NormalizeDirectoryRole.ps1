#Requires -Version 7.4

function ConvertTo-EntraPostureDirectoryRoleEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph directoryRole object (GET /v1.0/directoryRoles) into a
        canonical Entity record.

        .DESCRIPTION
        Uses roleTemplateId, not the directoryRole's own 'id', as this entity's stable entityId.
        Graph's 'id' on this endpoint identifies the tenant's *activation instance* of the role
        (it changes if the role is ever deactivated and reactivated); 'roleTemplateId' is the
        stable, documented, well-known GUID for the role definition itself (e.g. Global
        Administrator is always 62e90394-69f5-4237-9190-012177145e10) and is also what
        roleEligibilityScheduleInstances/roleAssignmentScheduleInstances key their
        roleDefinitionId against. Using the instance 'id' here would make relationship
        correlation across those endpoints silently wrong.

        Field allowlist per section 8.4: id, displayName, description, roleTemplateId only --
        this endpoint's response carries nothing else of interest for v1.

        .PARAMETER RawRole
        One element of the Graph response's 'value' array, as an ordered dictionary (from
        Send-EntraPostureRequest's strict-parsed results).

        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt
        UTC ISO 8601 string, captured once per collector run (not per record) so every entity
        from the same collection pass shares an identical timestamp.

        .OUTPUTS
        Ordered dictionary matching entity.schema.json.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawRole,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawRole.Contains('roleTemplateId') -or [string]::IsNullOrWhiteSpace([string]$RawRole['roleTemplateId'])) {
        throw "ConvertTo-EntraPostureDirectoryRoleEntity: raw directoryRole record has no roleTemplateId -- refusing to normalize with an unstable entityId."
    }

    return [ordered]@{
        entityId         = [string]$RawRole['roleTemplateId']
        entityType       = 'DirectoryRole'
        tenantScope      = $TenantScope
        displayName      = if ($RawRole.Contains('displayName')) { $RawRole['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            description          = if ($RawRole.Contains('description')) { $RawRole['description'] } else { $null }
            roleTemplateId       = [string]$RawRole['roleTemplateId']
            activationInstanceId = if ($RawRole.Contains('id')) { [string]$RawRole['id'] } else { $null }
        }
        redacted         = $false
    }
}
