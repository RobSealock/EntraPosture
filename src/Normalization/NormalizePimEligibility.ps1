#Requires -Version 7.4

function ConvertTo-EntraPosturePimEligibilityRelationship {
    <#
        .SYNOPSIS
        Normalizes one raw Graph unifiedRoleEligibilityScheduleInstance
        (GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances) into a canonical
        Relationship record.

        .DESCRIPTION
        targetEntityId uses 'roleDefinitionId' directly, with no separate correlation/lookup
        step -- this endpoint's roleDefinitionId is documented to key against the same stable
        role-template GUID space as directoryRoles' own 'roleTemplateId', which is exactly why
        ConvertTo-EntraPostureDirectoryRoleEntity (Phase 5) chose roleTemplateId as that
        entity's entityId in the first place ("which is also what
        roleEligibilityScheduleInstances/roleAssignmentScheduleInstances key their
        roleDefinitionId against" -- see that function's own DESCRIPTION). relationshipType is
        always 'PimEligible'; assignmentState reflects whether the eligibility window has
        already started ('Eligible') or is scheduled for the future ('PendingActivation'),
        derived from comparing startDateTime to -CollectedAt rather than trusting a status field
        this endpoint does not return.

        .PARAMETER RawInstance
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt
        Also used as the comparison point for deriving assignmentState.

        .OUTPUTS
        Ordered dictionary matching relationship.schema.json.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawInstance,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    foreach ($requiredField in @('principalId', 'roleDefinitionId')) {
        if (-not $RawInstance.Contains($requiredField) -or [string]::IsNullOrWhiteSpace([string]$RawInstance[$requiredField])) {
            throw "ConvertTo-EntraPosturePimEligibilityRelationship: raw eligibility instance is missing required field '$requiredField'."
        }
    }

    $principalId = [string]$RawInstance['principalId']
    $roleDefinitionId = [string]$RawInstance['roleDefinitionId']
    $startDateTime = if ($RawInstance.Contains('startDateTime')) { $RawInstance['startDateTime'] } else { $null }
    $endDateTime = if ($RawInstance.Contains('endDateTime')) { $RawInstance['endDateTime'] } else { $null }
    $directoryScopeId = if ($RawInstance.Contains('directoryScopeId')) { [string]$RawInstance['directoryScopeId'] } else { '/' }

    $assignmentState = 'Eligible'
    if ($startDateTime) {
        $start = [datetimeoffset]::Parse($startDateTime, [System.Globalization.CultureInfo]::InvariantCulture)
        $collected = [datetimeoffset]::Parse($CollectedAt, [System.Globalization.CultureInfo]::InvariantCulture)
        if ($start -gt $collected) {
            $assignmentState = 'PendingActivation'
        }
    }

    return [ordered]@{
        relationshipId   = "$principalId::$roleDefinitionId::PimEligible"
        sourceEntityId   = $principalId
        targetEntityId   = $roleDefinitionId
        relationshipType = 'PimEligible'
        assignmentState  = $assignmentState
        scope            = if ([string]::IsNullOrWhiteSpace($directoryScopeId) -or $directoryScopeId -eq '/') { 'directory' } else { $directoryScopeId }
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
