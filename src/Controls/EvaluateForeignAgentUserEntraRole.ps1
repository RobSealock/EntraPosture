#Requires -Version 7.4

function Test-EntraPostureForeignAgentUserEntraRoleControl {
    <#
        .SYNOPSIS
        AGT-011's evaluator: checks each foreign AgentUser for an Active DirectoryRoleAssignment
        to a curated Tier-0 role.

        .DESCRIPTION
        Same shape as AGT-004's evaluator, over the AgentUser population instead of AgentIdentity,
        using Get-EntraPostureAgentUserForeignMap ("foreign" derived transitively through
        identityParentId -> parent AgentIdentity -> that identity's own blueprint principal's
        appOwnerOrganizationId -- a real, documented indirection, not a direct field on AgentUser
        itself; see that function's own DESCRIPTION). An AgentUser correlates against
        DirectoryRoleAssignment by its own entityId directly (an agent user is itself a
        user-derived principal, and can hold a role assignment independently of its parent agent
        identity's own assignments). An AgentUser whose foreign-ness is unresolvable is excluded
        from this control's population entirely, the same reasoning AGT-004's evaluator
        documents. Never produces NotEvaluated or Error status -- assigned by the orchestration
        layer, per AGT-011.psd1's expectedResultSemantics.

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
    $foreignUsers = @($agentUsers | Where-Object { $foreignMap.Contains($_.entityId) -and $foreignMap[$_.entityId] -eq $true })

    if (@($foreignUsers).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AGT-011-NO-FOREIGN-AGENT-USERS'
                Rationale          = 'No AgentUser entity was confirmed foreign (via its parent agent identity) in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($agentUser in $foreignUsers) {
        $activeAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -SourceEntityId $agentUser.entityId
        $activeAssignments = @($activeAssignments | Where-Object { $_.assignmentState -eq 'Active' -and $tierZeroRoleIds -contains $_.targetEntityId })

        $evidenceRef = @([ordered]@{ entityId = $agentUser.entityId; entityType = 'AgentUser' })
        foreach ($assignment in $activeAssignments) {
            $evidenceRef += [ordered]@{ entityId = $assignment.targetEntityId; entityType = 'DirectoryRole' }
        }

        if (@($activeAssignments).Count -gt 0) {
            [ordered]@{
                Scope              = $agentUser.entityId
                Status             = 'Fail'
                ReasonCode         = 'AGT-011-FOREIGN-TIER-ZERO-ROLE'
                Rationale          = "Foreign agent user '$($agentUser.displayName)' holds an Active assignment to a curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $agentUser.entityId
                Status             = 'Pass'
                ReasonCode         = 'AGT-011-NO-TIER-ZERO-ROLE'
                Rationale          = "Foreign agent user '$($agentUser.displayName)' holds no Active assignment to any curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
