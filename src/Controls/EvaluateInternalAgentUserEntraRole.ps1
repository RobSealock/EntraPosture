#Requires -Version 7.4

function Test-EntraPostureInternalAgentUserEntraRoleControl {
    <#
        .SYNOPSIS
        AGT-013's evaluator: checks each AgentUser entity whose parent AgentIdentity is confirmed
        internal (non-foreign) for an Active DirectoryRoleAssignment to a curated Tier-0 role.

        .DESCRIPTION
        Left "blocked" in the original design spec (15-feature-parity-matrix.md section 11)
        pending live-tenant confirmation of Microsoft's own platform claim that agent users
        operate under "no privileged admin role assignments" -- re-evaluated 2026-08-08: this is
        a defensive, rarely-expected-to-fire check the same way EM-002's
        EM002-ASSIGNMENT-PAST-EXPIRATION was built despite a similar unresolved reachability
        question (see that control's own provenance notes) -- if the platform claim holds, this
        control simply never Fails in practice; if it doesn't, that is exactly the kind of gap
        this project exists to surface. Same evaluator shape as AGT-011's foreign counterpart,
        internal population. Never produces NotEvaluated or Error status -- assigned by the
        orchestration layer, per AGT-013.psd1's expectedResultSemantics.

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

    $tierZeroRoleNames = @('Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator')

    $roles = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'DirectoryRole'
    $tierZeroRoleIds = @(@($roles | Where-Object { $tierZeroRoleNames -contains $_.displayName }) | ForEach-Object { $_.entityId })

    $agentUsers = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AgentUser'
    $foreignMap = Get-EntraPostureAgentUserForeignMap -EvidenceProvider $EvidenceProvider
    $internalUsers = @($agentUsers | Where-Object { $foreignMap.Contains($_.entityId) -and $foreignMap[$_.entityId] -eq $false })

    if (@($internalUsers).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'AGT-013-NO-INTERNAL-AGENT-USERS'
                Rationale = 'No AgentUser entity was confirmed internal (non-foreign, via its parent agent identity) in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($agentUser in $internalUsers) {
        $activeAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -SourceEntityId $agentUser.entityId
        $activeAssignments = @($activeAssignments | Where-Object { $_.assignmentState -eq 'Active' -and $tierZeroRoleIds -contains $_.targetEntityId })

        $evidenceRef = @([ordered]@{ entityId = $agentUser.entityId; entityType = 'AgentUser' })
        foreach ($assignment in $activeAssignments) { $evidenceRef += [ordered]@{ entityId = $assignment.targetEntityId; entityType = 'DirectoryRole' } }

        if (@($activeAssignments).Count -gt 0) {
            [ordered]@{
                Scope = $agentUser.entityId; Status = 'Fail'; ReasonCode = 'AGT-013-INTERNAL-TIER-ZERO-ROLE'
                Rationale = "Internal agent user '$($agentUser.displayName)' holds an Active assignment to a curated Tier-0 Entra ID role -- Microsoft's own documentation states agent users should never hold privileged admin role assignments."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $agentUser.entityId; Status = 'Pass'; ReasonCode = 'AGT-013-NO-TIER-ZERO-ROLE'
                Rationale = "Internal agent user '$($agentUser.displayName)' holds no Active assignment to any curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
