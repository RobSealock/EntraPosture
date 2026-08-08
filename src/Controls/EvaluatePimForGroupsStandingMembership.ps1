#Requires -Version 7.4

function Test-EntraPosturePimForGroupsStandingMembershipControl {
    <#
        .SYNOPSIS
        PIMG-001's evaluator: for each role-assignable group that has PIM-for-Groups membership
        eligibility configured, checks whether any of its actual (TransitiveMemberOf) members
        bypass PIM entirely -- present as a direct member with no corresponding PimEligible or
        PimActive relationship for that principal+group.

        .DESCRIPTION
        The same "presence of a governance mechanism proves nothing if bypassed" logic
        PIM-002/EvaluateStandingTierZeroAssignment.ps1 already applies to directory roles,
        generalized to groups: TransitiveMemberOf (collected by the existing Groups collector,
        unrelated to and independent of PIM-for-Groups) is the ground truth for who is actually a
        member; PimEligible/PimActive (accessId 'member', collected by
        CollectPimForGroups.ps1) is what PIM itself knows about. A member present in the former
        but absent from both of the latter was added through the ordinary Groups API, bypassing
        PIM-for-Groups entirely, even though the group has PIM-for-Groups membership eligibility
        configured. Scoped to groups with at least one PimEligible (accessId 'member') record --
        a role-assignable group with no PIM-for-Groups membership eligibility configured at all
        has nothing for this control to check (PIMG-001.psd1's own applicability). Never produces
        NotEvaluated or Error status -- assigned by the orchestration layer, per PIMG-001.psd1's
        expectedResultSemantics.

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

    $groupsWithPimConfigured = [System.Collections.Generic.List[object]]::new()
    foreach ($group in $roleAssignableGroups) {
        $eligibility = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'PimEligible' -TargetEntityId $group.entityId
        $eligibility = @($eligibility | Where-Object { $_.scope -eq 'member' })
        if (@($eligibility).Count -gt 0) {
            $groupsWithPimConfigured.Add($group)
        }
    }

    if ($groupsWithPimConfigured.Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'PIMG-001-NO-GROUPS-WITH-PIM-CONFIGURED'
                Rationale          = 'No role-assignable Group entity has PIM-for-Groups membership eligibility configured in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($group in $groupsWithPimConfigured) {
        $members = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'TransitiveMemberOf' -TargetEntityId $group.entityId

        $pimKnownPrincipalIds = [System.Collections.Generic.HashSet[string]]::new()
        $groupEligible = @(Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'PimEligible' -TargetEntityId $group.entityId | Where-Object { $_.scope -eq 'member' })
        $groupActive = @(Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'PimActive' -TargetEntityId $group.entityId | Where-Object { $_.scope -eq 'member' })
        foreach ($rel in $groupEligible) { [void]$pimKnownPrincipalIds.Add($rel.sourceEntityId) }
        foreach ($rel in $groupActive) { [void]$pimKnownPrincipalIds.Add($rel.sourceEntityId) }

        $bypassPrincipalIds = @($members | Where-Object { -not $pimKnownPrincipalIds.Contains($_.sourceEntityId) } | ForEach-Object { $_.sourceEntityId })

        $evidenceRef = @([ordered]@{ entityId = $group.entityId; entityType = 'Group' })
        foreach ($principalId in $bypassPrincipalIds) {
            $evidenceRef += [ordered]@{ entityId = $principalId; entityType = 'Unknown' }
        }

        if (@($bypassPrincipalIds).Count -gt 0) {
            [ordered]@{
                Scope              = $group.entityId
                Status             = 'Fail'
                ReasonCode         = 'PIMG-001-STANDING-MEMBERSHIP-OUTSIDE-PIM'
                Rationale          = "Role-assignable group '$($group.displayName)' has PIM-for-Groups membership eligibility configured, but $(@($bypassPrincipalIds).Count) current member(s) hold standing membership PIM has no record of at all."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $group.entityId
                Status             = 'Pass'
                ReasonCode         = 'PIMG-001-MEMBERSHIP-GOVERNED-BY-PIM'
                Rationale          = "Role-assignable group '$($group.displayName)' has every current member accounted for by a PIM-for-Groups eligibility or active-assignment record."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
