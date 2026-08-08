#Requires -Version 7.4

function Test-EntraPostureAgentUserCapGroupOwnershipControl {
    <#
        .SYNOPSIS
        AGT-015's evaluator: checks each AgentUser that owns at least one Group for whether any
        owned group is itself referenced in a Conditional Access policy's
        includeGroups/excludeGroups condition.

        .DESCRIPTION
        Relational correlation across three evidence domains: OwnerOf (AgentUser -> Group,
        collected by CollectAgentUsers.ps1's ownedObjects N+1 fetch, filtered to group-typed
        results at normalization time), and ConditionalAccessPolicy's own
        conditions.users.includeGroups/excludeGroups arrays (already collected, no new evidence
        needed for that half). An AgentUser that owns zero groups at all produces zero results
        for that user (nothing to check), the same "zero results, not Pass/Fail" shape PIM-002
        already established for a role with zero assignments -- only agent users with at least
        one owned group are evaluated. Never produces NotEvaluated or Error status -- assigned by
        the orchestration layer, per AGT-015.psd1's expectedResultSemantics.

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

    $agentUsers = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AgentUser'
    $caPolicies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ConditionalAccessPolicy'

    $capReferencedGroupIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($policy in $caPolicies) {
        foreach ($groupId in @($policy.properties.conditions.users.includeGroups)) { [void]$capReferencedGroupIds.Add([string]$groupId) }
        foreach ($groupId in @($policy.properties.conditions.users.excludeGroups)) { [void]$capReferencedGroupIds.Add([string]$groupId) }
    }

    $usersWithOwnedGroups = [System.Collections.Generic.List[object]]::new()
    foreach ($agentUser in $agentUsers) {
        $ownedGroups = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'OwnerOf' -SourceEntityId $agentUser.entityId
        if (@($ownedGroups).Count -gt 0) {
            $usersWithOwnedGroups.Add([ordered]@{ AgentUser = $agentUser; OwnedGroups = @($ownedGroups) })
        }
    }

    if ($usersWithOwnedGroups.Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AGT-015-NO-AGENT-USER-GROUP-OWNERSHIP'
                Rationale          = 'No AgentUser entity owns any Group in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($entry in $usersWithOwnedGroups) {
        $agentUser = $entry.AgentUser
        $capOwnedGroupIds = @($entry.OwnedGroups | Where-Object { $capReferencedGroupIds.Contains([string]$_.targetEntityId) } | ForEach-Object { [string]$_.targetEntityId })

        $evidenceRef = @([ordered]@{ entityId = $agentUser.entityId; entityType = 'AgentUser' })
        foreach ($groupId in $capOwnedGroupIds) {
            $evidenceRef += [ordered]@{ entityId = $groupId; entityType = 'Group' }
        }

        if (@($capOwnedGroupIds).Count -gt 0) {
            [ordered]@{
                Scope              = $agentUser.entityId
                Status             = 'Fail'
                ReasonCode         = 'AGT-015-OWNS-CAP-GROUP'
                Rationale          = "Agent user '$($agentUser.displayName)' owns at least one Group referenced in a Conditional Access policy's user condition."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $agentUser.entityId
                Status             = 'Pass'
                ReasonCode         = 'AGT-015-NO-CAP-GROUP-OWNERSHIP'
                Rationale          = "Agent user '$($agentUser.displayName)' owns at least one Group, but none are referenced in any Conditional Access policy's user condition."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
