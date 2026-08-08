#Requires -Version 7.4

function Test-EntraPostureSensitiveGroupProtectionControl {
    <#
        .SYNOPSIS
        GRP-005's evaluator: counts each role-assignable group's TransitiveMemberOf
        relationships and checks the count against a bounded threshold.

        .DESCRIPTION
        One result per Group entity flagged isAssignableToRole=true -- the applicable unit is
        the group's own current transitive membership, mirroring PRIV-001's per-role aggregate
        pattern. Never produces NotEvaluated or Error status -- assigned by the orchestration
        layer, per GRP-005.psd1's expectedResultSemantics.

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

    if (@($roleAssignableGroups).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'GRP-005-NO-ROLE-ASSIGNABLE-GROUPS'
                Rationale          = 'No Group entity with isAssignableToRole=true was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $threshold = 5

    $evaluationResults = @(foreach ($group in $roleAssignableGroups) {
        # No @() wrapper around the call -- Get-EntraPostureRelationship already
        # comma-protects its return (`return ,@($records)`); wrapping the call site in @() too
        # double-wraps it into a 1-element array whose sole element is the real records array,
        # confirmed directly (Count read as 1 regardless of the true member count) while building
        # this control's tests. Consistent with the established rule that a comma-protected
        # return value should be forwarded/consumed with neither `,` nor an extra `@()` at the
        # call site -- PRIV-001's evaluator already follows this (Get-EntraPostureRelationship
        # called bare, then re-wrapped only *after* a Where-Object pipeline, which is a different,
        # safe case).
        $members = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'TransitiveMemberOf' -TargetEntityId $group.entityId
        $count = $members.Count

        $evidenceRef = @([ordered]@{ entityId = $group.entityId; entityType = 'Group' })
        foreach ($member in $members) {
            $evidenceRef += [ordered]@{ entityId = $member.sourceEntityId; entityType = 'Unknown' }
        }

        if ($count -gt $threshold) {
            [ordered]@{
                Scope              = $group.entityId
                Status             = 'Fail'
                ReasonCode         = 'GRP-005-EXCESSIVE-TRANSITIVE-MEMBERSHIP'
                Rationale          = "Role-assignable group '$($group.displayName)' has $count transitive member(s), exceeding the recommended bound of $threshold for a curated, reviewable privilege boundary."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $group.entityId
                Status             = 'Pass'
                ReasonCode         = 'GRP-005-MEMBERSHIP-WITHIN-BOUND'
                Rationale          = "Role-assignable group '$($group.displayName)' has $count transitive member(s), within the recommended bound of $threshold."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
