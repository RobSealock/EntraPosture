#Requires -Version 7.4

function Test-EntraPosturePimForGroupsPermanentAssignmentControl {
    <#
        .SYNOPSIS
        PIMG-002's evaluator: for each role-assignable group with at least one PIM-for-Groups
        active-assignment schedule instance, checks whether any instance has no expiration.

        .DESCRIPTION
        Directly parallel to PIM-005's "Tier-0 Roles Allow Permanent Active Assignments" check,
        applied to groups -- but reads validity.endDateTime directly off each collected PimActive
        relationship (null means no expiration, confirmed directly against the live "List
        assignmentScheduleInstances" Graph reference page's own example response, re-fetched
        2026-08-07) rather than a nested scheduleInfo.expiration.type the original design spec
        speculated about before that endpoint was actually checked -- see
        ConvertTo-EntraPosturePimGroupActiveRelationship's own DESCRIPTION for the correction.
        Unlike PIM-005 (which reads a role's PIM *policy setting*, i.e. whether a permanent
        assignment is allowed at all), this control has no policy-setting evidence source for
        PIM-for-Groups and instead examines the group's actual current active-assignment
        instances for whether any is, in fact, permanent right now. Scoped to groups with at
        least one PimActive (accessId 'member' or 'owner') record -- a role-assignable group with
        no PIM-for-Groups active assignment at all has nothing for this control to check. Never
        produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        PIMG-002.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $groups = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'Group'
    $roleAssignableGroups = @($groups | Where-Object { [bool]$_.properties.isAssignableToRole })

    $groupsWithActiveAssignments = [System.Collections.Generic.List[object]]::new()
    foreach ($group in $roleAssignableGroups) {
        $active = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'PimActive' -TargetEntityId $group.entityId
        if (@($active).Count -gt 0) {
            $groupsWithActiveAssignments.Add([ordered]@{ Group = $group; ActiveAssignments = @($active) })
        }
    }

    if ($groupsWithActiveAssignments.Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'PIMG-002-NO-GROUPS-WITH-ACTIVE-ASSIGNMENTS'
                Rationale          = 'No role-assignable Group entity has a PIM-for-Groups active-assignment schedule instance in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($entry in $groupsWithActiveAssignments) {
        $group = $entry.Group
        $permanentAssignments = @($entry.ActiveAssignments | Where-Object { $null -eq $_.validity.endDateTime })

        $evidenceRef = @([ordered]@{ entityId = $group.entityId; entityType = 'Group' })

        if (@($permanentAssignments).Count -gt 0) {
            [ordered]@{
                Scope              = $group.entityId
                Status             = 'Fail'
                ReasonCode         = 'PIMG-002-PERMANENT-ASSIGNMENT-ALLOWED'
                Rationale          = "Role-assignable group '$($group.displayName)' has $(@($permanentAssignments).Count) PIM-for-Groups active assignment(s) with no expiration."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $group.entityId
                Status             = 'Pass'
                ReasonCode         = 'PIMG-002-EXPIRATION-REQUIRED'
                Rationale          = "Role-assignable group '$($group.displayName)' has every PIM-for-Groups active assignment set to expire."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
