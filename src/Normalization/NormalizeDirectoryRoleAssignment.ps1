#Requires -Version 7.4

function ConvertTo-EntraPostureDirectoryRoleAssignmentRelationship {
    <#
        .SYNOPSIS
        Normalizes one raw Graph directoryRole member (GET /v1.0/directoryRoles/{id}/members)
        into a canonical Relationship record.

        .DESCRIPTION
        Members returned by this endpoint are, by definition, current active holders of the
        role -- Graph does not return former/pending members here -- so assignmentState is
        always 'Active'. Field allowlist: id only (displayName/@odata.type are not persisted;
        this relationship's job is to record *that* the assignment exists and to whom, not to
        duplicate the member's own entity attributes -- a User entity, if collected separately,
        is the place for those).

        .PARAMETER RawMember
        One element of the Graph response's 'value' array.

        .PARAMETER RoleEntityId
        The DirectoryRole entity's entityId (its roleTemplateId, per
        ConvertTo-EntraPostureDirectoryRoleEntity), not the member endpoint's own role
        instance ID.

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
        [string]$RoleEntityId,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawMember.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawMember['id'])) {
        throw 'ConvertTo-EntraPostureDirectoryRoleAssignmentRelationship: raw member record has no id.'
    }
    $memberId = [string]$RawMember['id']

    return [ordered]@{
        relationshipId   = "$memberId::$RoleEntityId::DirectoryRoleAssignment"
        sourceEntityId   = $memberId
        targetEntityId   = $RoleEntityId
        relationshipType = 'DirectoryRoleAssignment'
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
            isTransitive  = $false
        }
    }
}
