#Requires -Version 7.4

function ConvertTo-EntraPostureOwnerOfRelationship {
    <#
        .SYNOPSIS
        Normalizes one raw Graph directoryObject returned from an owners-listing endpoint (e.g.
        GET /v1.0/applications/{id}/owners) into a canonical Relationship record --
        relationship.schema.json's 'OwnerOf' enum value, reserved since Phase 3 but unused by
        any collector until AGT-017 (VNext build order item 13) needed it for the first time.

        .DESCRIPTION
        Generic across every ownership relationship this project collects (currently: an
        agentIdentityBlueprint's owners, for AGT-017), not blueprint-specific -- the owners
        endpoint shape (a directoryObject with at minimum an 'id') is identical regardless of
        which owned-object type is being queried, matching the collector-per-endpoint,
        normalizer-per-shape split every other relationship normalizer in this project already
        follows.

        .PARAMETER RawOwner
        One element of the owners endpoint's 'value' array.

        .PARAMETER OwnedEntityId
        The entityId of the object being owned (e.g. the AgentIdentityBlueprint's own entityId).

        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching relationship.schema.json (relationshipType 'OwnerOf').
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawOwner,

        [Parameter(Mandatory)]
        [string]$OwnedEntityId,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawOwner.Contains('id') -or [string]::IsNullOrWhiteSpace([string]$RawOwner['id'])) {
        throw 'ConvertTo-EntraPostureOwnerOfRelationship: raw owner record has no id.'
    }
    $ownerId = [string]$RawOwner['id']

    return [ordered]@{
        relationshipId   = "$ownerId::$OwnedEntityId::OwnerOf"
        sourceEntityId   = $ownerId
        targetEntityId   = $OwnedEntityId
        relationshipType = 'OwnerOf'
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
