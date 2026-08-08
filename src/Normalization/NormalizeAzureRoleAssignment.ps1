#Requires -Version 7.4

function ConvertTo-EntraPostureAzureRoleAssignmentEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Azure Resource Manager roleAssignment object
        (GET /{scope}/providers/Microsoft.Authorization/roleAssignments) into a canonical
        Entity record.

        .DESCRIPTION
        Field allowlist per section 8.4: id, name, and properties.{roleDefinitionId,
        principalId, principalType, scope, createdOn} only. displayName is explicit null --
        an ARM role assignment has no display name of its own (unlike an Entra directory
        object), so this is exactly the "explicit null, not absent" case entity.schema.json's
        description calls out.

        Phase 6 adds inheritedAtQueriedScope/queriedScope: ARM's List role assignments API,
        called without '$filter=atScope()', returns every assignment that applies AT a given
        scope, including ones actually *defined* at an ancestor scope (a management group or
        parent subscription) and inherited down -- this is the "inherited Azure RBAC
        correlation" Phase 6 names explicitly. Each returned assignment's own
        'properties.scope' field states where it was actually defined; comparing that against
        the scope the caller actually queried (-QueriedScope) is the entire correlation: equal
        means a direct assignment at the queried scope, different means inherited from that
        ancestor.

        .PARAMETER RawAssignment
        One element of the ARM response's 'value' array.

        .PARAMETER QueriedScope
        The ARM scope path this record was fetched from (i.e. what the collector passed as
        -Scope), not necessarily where the assignment itself is defined.

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
        [System.Collections.Specialized.OrderedDictionary]$RawAssignment,

        [Parameter(Mandatory)]
        [string]$QueriedScope,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawAssignment.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawAssignment['id'])) {
        throw 'ConvertTo-EntraPostureAzureRoleAssignmentEntity: raw roleAssignment record has no id.'
    }

    $props = if ($RawAssignment.Contains('properties')) { $RawAssignment['properties'] } else { $null }
    $definedScope = if ($props -and $props.Contains('scope')) { [string]$props['scope'] } else { $null }
    # Ordinal, case-insensitive comparison -- ARM resource ID casing is not guaranteed
    # consistent between the scope a caller supplies and the scope ARM echoes back on a
    # returned assignment (confirmed inconsistent casing is a known ARM API quirk generally,
    # not specific to this endpoint); never culture-sensitive string comparison either way.
    $isInherited = $definedScope -and -not $definedScope.Equals($QueriedScope, [StringComparison]::OrdinalIgnoreCase)

    return [ordered]@{
        entityId         = [string]$RawAssignment['id']
        entityType       = 'AzureRoleAssignment'
        tenantScope      = $TenantScope
        displayName      = $null
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            name                    = if ($RawAssignment.Contains('name')) { [string]$RawAssignment['name'] } else { $null }
            roleDefinitionId        = if ($props -and $props.Contains('roleDefinitionId')) { $props['roleDefinitionId'] } else { $null }
            principalId             = if ($props -and $props.Contains('principalId')) { $props['principalId'] } else { $null }
            principalType           = if ($props -and $props.Contains('principalType')) { $props['principalType'] } else { $null }
            scope                   = $definedScope
            createdOn               = if ($props -and $props.Contains('createdOn')) { $props['createdOn'] } else { $null }
            queriedScope            = $QueriedScope
            inheritedAtQueriedScope = [bool]$isInherited
        }
        redacted         = $false
    }
}
