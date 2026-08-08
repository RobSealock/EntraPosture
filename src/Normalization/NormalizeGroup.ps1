#Requires -Version 7.4

function ConvertTo-EntraPostureGroupEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph group object (GET /v1.0/groups) into a canonical Entity record.

        .DESCRIPTION
        Field allowlist per section 8.4: id, displayName, groupTypes, securityEnabled,
        mailEnabled, isAssignableToRole. isAssignableToRole is specifically load-bearing for
        PIM-for-Groups/role-assignable-group findings (a role-assignable group is a materially
        different privilege-management surface than an ordinary security group).

        .PARAMETER RawGroup
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
        [System.Collections.Specialized.OrderedDictionary]$RawGroup,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawGroup.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawGroup['id'])) {
        throw 'ConvertTo-EntraPostureGroupEntity: raw group record has no id.'
    }

    return [ordered]@{
        entityId         = [string]$RawGroup['id']
        entityType       = 'Group'
        tenantScope      = $TenantScope
        displayName      = if ($RawGroup.Contains('displayName')) { $RawGroup['displayName'] } else { $null }
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            groupTypes         = @(if ($RawGroup.Contains('groupTypes')) { $RawGroup['groupTypes'] } else { @() })
            securityEnabled    = if ($RawGroup.Contains('securityEnabled')) { $RawGroup['securityEnabled'] } else { $null }
            mailEnabled        = if ($RawGroup.Contains('mailEnabled')) { $RawGroup['mailEnabled'] } else { $null }
            isAssignableToRole = if ($RawGroup.Contains('isAssignableToRole')) { $RawGroup['isAssignableToRole'] } else { $null }
        }
        redacted         = $false
    }
}

function ConvertTo-EntraPostureGroupTransitiveMembershipRelationship {
    <#
        .SYNOPSIS
        Normalizes one raw Graph transitiveMembers entry
        (GET /v1.0/groups/{groupId}/transitiveMembers) into a canonical Relationship record.

        .DESCRIPTION
        relationshipType 'TransitiveMemberOf' with validity.isTransitive = $true -- distinct
        from the (not currently collected in Phase 6) direct-membership edge, matching
        relationship.schema.json's existing 'isTransitive' field, which was defined in Phase 3
        specifically for this distinction. Members returned by this endpoint can be users,
        groups, service principals, or devices -- the relationship only records the member's
        entityId, not its type, matching the same "reference by ID, don't duplicate the
        member's own entity attributes" rationale as
        ConvertTo-EntraPostureDirectoryRoleAssignmentRelationship.

        .PARAMETER RawMember
        .PARAMETER GroupEntityId
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching relationship.schema.json.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawMember,

        [Parameter(Mandatory)]
        [string]$GroupEntityId,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawMember.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawMember['id'])) {
        throw 'ConvertTo-EntraPostureGroupTransitiveMembershipRelationship: raw member record has no id.'
    }
    $memberId = [string]$RawMember['id']

    return [ordered]@{
        relationshipId   = "$memberId::$GroupEntityId::TransitiveMemberOf"
        sourceEntityId   = $memberId
        targetEntityId   = $GroupEntityId
        relationshipType = 'TransitiveMemberOf'
        assignmentState  = 'Active'
        scope            = 'directory'
        provenance       = [ordered]@{
            collectorVersion = $CollectorVersion
            sourceEndpoint   = $SourceEndpoint
            collectedAt      = $CollectedAt
        }
        validity         = [ordered]@{
            startDateTime = $null
            endDateTime   = $null
            isTransitive  = $true
        }
    }
}
