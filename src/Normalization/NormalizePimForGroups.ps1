#Requires -Version 7.4

function ConvertTo-EntraPosturePimGroupEligibilityRelationship {
    <#
        .SYNOPSIS
        Normalizes one raw Graph privilegedAccessGroupEligibilityScheduleInstance
        (GET /v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances
        ?$filter=groupId eq '{groupId}') into a canonical Relationship record -- reuses the
        existing 'PimEligible' relationshipType (previously role-only, via
        NormalizePimEligibility.ps1) with a Group entity as the target instead of a DirectoryRole,
        rather than minting a new relationshipType. targetEntityId's GUID space (a Group's own
        entityId vs. a DirectoryRole's roleTemplateId) never collides in practice, and every
        caller filters by an explicit TargetEntityId it already knows the type of, so the two
        populations coexist safely in the same evidence file (VNext build order item 13,
        PIM-for-Groups).

        .DESCRIPTION
        accessId distinguishes membership eligibility ('member') from ownership eligibility
        ('owner') -- confirmed directly on the live "List eligibilityScheduleInstances" Graph
        reference page's own example response (re-fetched 2026-08-07), carried into 'scope' so a
        Group's membership-eligible and ownership-eligible principals are never conflated.
        assignmentState mirrors NormalizePimEligibility.ps1's own startDateTime-vs-CollectedAt
        derivation exactly, for the same reason.

        .PARAMETER RawInstance
        .PARAMETER GroupEntityId
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt
        Also used as the comparison point for deriving assignmentState.

        .OUTPUTS
        Ordered dictionary matching relationship.schema.json (relationshipType 'PimEligible').
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawInstance,

        [Parameter(Mandatory)]
        [string]$GroupEntityId,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawInstance.Contains('principalId') -or [string]::IsNullOrWhiteSpace([string]$RawInstance['principalId'])) {
        throw "ConvertTo-EntraPosturePimGroupEligibilityRelationship: raw eligibility instance is missing required field 'principalId'."
    }

    $principalId = [string]$RawInstance['principalId']
    $accessId = if ($RawInstance.Contains('accessId')) { [string]$RawInstance['accessId'] } else { 'member' }
    $startDateTime = if ($RawInstance.Contains('startDateTime')) { $RawInstance['startDateTime'] } else { $null }
    $endDateTime = if ($RawInstance.Contains('endDateTime')) { $RawInstance['endDateTime'] } else { $null }

    $assignmentState = 'Eligible'
    if ($startDateTime) {
        $start = [datetimeoffset]::Parse($startDateTime, [System.Globalization.CultureInfo]::InvariantCulture)
        $collected = [datetimeoffset]::Parse($CollectedAt, [System.Globalization.CultureInfo]::InvariantCulture)
        if ($start -gt $collected) {
            $assignmentState = 'PendingActivation'
        }
    }

    return [ordered]@{
        relationshipId   = "$principalId::$GroupEntityId::$accessId::PimEligible"
        sourceEntityId   = $principalId
        targetEntityId   = $GroupEntityId
        relationshipType = 'PimEligible'
        assignmentState  = $assignmentState
        scope            = $accessId
        provenance       = [ordered]@{
            collectorVersion = $CollectorVersion
            sourceEndpoint   = $SourceEndpoint
            collectedAt      = $CollectedAt
        }
        validity         = [ordered]@{
            startDateTime = $startDateTime
            endDateTime   = $endDateTime
            isTransitive  = $false
        }
    }
}

function ConvertTo-EntraPosturePimGroupActiveRelationship {
    <#
        .SYNOPSIS
        Normalizes one raw Graph privilegedAccessGroupAssignmentScheduleInstance
        (GET /v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances
        ?$filter=groupId eq '{groupId}') into a canonical Relationship record -- the first real
        use of relationship.schema.json's 'PimActive' enum value, reserved since Phase 3.

        .DESCRIPTION
        Deliberately a distinct relationshipType from 'DirectoryRoleAssignment' (which represents
        the different, endpoint-specific concept of an Entra directory role's current active
        members) and from the plain 'TransitiveMemberOf' this project's Groups collector already
        produces: a PimActive record specifically means "this principal's group
        membership/ownership is being tracked as a PIM-governed schedule instance," which is
        exactly the signal PIMG-001 needs to distinguish a group member PIM knows about (Active
        via activation, or Assigned by an admin through the PIM API) from one added directly
        through the ordinary Groups API and invisible to PIM entirely (present only in
        TransitiveMemberOf, absent here) -- PIMG-001.psd1's own applicability section documents
        this correlation. endDateTime null means no expiration, confirmed directly against the
        live "List assignmentScheduleInstances" Graph reference page's own example response
        (re-fetched 2026-08-07) -- PIMG-002 reads this field directly, not a nested
        scheduleInfo.expiration.type the design spec speculated about before this endpoint was
        actually checked.

        .PARAMETER RawInstance
        .PARAMETER GroupEntityId
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching relationship.schema.json (relationshipType 'PimActive').
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawInstance,

        [Parameter(Mandatory)]
        [string]$GroupEntityId,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    if (-not $RawInstance.Contains('principalId') -or [string]::IsNullOrWhiteSpace([string]$RawInstance['principalId'])) {
        throw "ConvertTo-EntraPosturePimGroupActiveRelationship: raw assignment instance is missing required field 'principalId'."
    }

    $principalId = [string]$RawInstance['principalId']
    $accessId = if ($RawInstance.Contains('accessId')) { [string]$RawInstance['accessId'] } else { 'member' }
    $startDateTime = if ($RawInstance.Contains('startDateTime')) { $RawInstance['startDateTime'] } else { $null }
    $endDateTime = if ($RawInstance.Contains('endDateTime')) { $RawInstance['endDateTime'] } else { $null }

    return [ordered]@{
        relationshipId   = "$principalId::$GroupEntityId::$accessId::PimActive"
        sourceEntityId   = $principalId
        targetEntityId   = $GroupEntityId
        relationshipType = 'PimActive'
        assignmentState  = 'Active'
        scope            = $accessId
        provenance       = [ordered]@{
            collectorVersion = $CollectorVersion
            sourceEndpoint   = $SourceEndpoint
            collectedAt      = $CollectedAt
        }
        validity         = [ordered]@{
            startDateTime = $startDateTime
            endDateTime   = $endDateTime
            isTransitive  = $false
        }
    }
}
