#Requires -Version 7.4

function ConvertTo-EntraPostureAzureManagementGroupEntity {
    <#
        .SYNOPSIS
        Normalizes one raw ARM managementGroup object
        (GET /providers/Microsoft.Management/managementGroups) into a canonical Entity record.

        .DESCRIPTION
        Field allowlist per section 8.4: name (the management group ID), properties.displayName,
        properties.tenantId. entityId is the group's own ARM scope path
        ('/providers/Microsoft.Management/managementGroups/{id}'), matching
        ConvertTo-EntraPostureAzureSubscriptionEntity's same "usable directly as a -Scope
        argument" design.

        .PARAMETER RawManagementGroup
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
        [System.Collections.Specialized.OrderedDictionary]$RawManagementGroup,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawManagementGroup.Contains('name') -or [string]::IsNullOrWhiteSpace([string]$RawManagementGroup['name'])) {
        throw 'ConvertTo-EntraPostureAzureManagementGroupEntity: raw managementGroup record has no name.'
    }
    $groupId = [string]$RawManagementGroup['name']
    $props = if ($RawManagementGroup.Contains('properties')) { $RawManagementGroup['properties'] } else { $null }

    return [ordered]@{
        entityId         = "/providers/Microsoft.Management/managementGroups/$groupId"
        entityType       = 'AzureManagementGroup'
        tenantScope      = $TenantScope
        displayName      = if ($props -and $props.Contains('displayName')) { $props['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            managementGroupId = $groupId
            tenantId          = if ($props -and $props.Contains('tenantId')) { $props['tenantId'] } else { $null }
        }
        redacted         = $false
    }
}
