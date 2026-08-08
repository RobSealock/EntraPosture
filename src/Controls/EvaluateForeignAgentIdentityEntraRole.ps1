#Requires -Version 7.4

function Test-EntraPostureForeignAgentIdentityEntraRoleControl {
    <#
        .SYNOPSIS
        AGT-004's evaluator: checks each foreign AgentIdentity for an Active DirectoryRoleAssignment
        to a curated Tier-0 role.

        .DESCRIPTION
        Relational: uses Get-EntraPostureAgentIdentityForeignMap (shared with AGT-005/008/009)
        to determine each AgentIdentity's foreign-ness, then correlates the foreign subset
        against existing DirectoryRoleAssignment evidence by principal ID -- reuses evidence, no
        new role-resolution logic, the same reuse discipline EM-001 applied to
        Group.isAssignableToRole. An AgentIdentity whose foreign-ness is unresolvable (the
        foreign map's $null case) is excluded from this control's population entirely -- it is
        neither confirmed foreign nor confirmed internal, so neither this control nor AGT-008 can
        meaningfully classify it; this produces zero results for that identity, the same "nothing
        to check" shape PIM-002 already established for a Tier-0 role with zero active
        assignments. Never produces NotEvaluated or Error status -- assigned by the orchestration
        layer, per AGT-004.psd1's expectedResultSemantics.

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

    $agentIdentities = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AgentIdentity'
    $foreignMap = Get-EntraPostureAgentIdentityForeignMap -EvidenceProvider $EvidenceProvider
    $foreignIdentities = @($agentIdentities | Where-Object { $foreignMap.Contains($_.entityId) -and $foreignMap[$_.entityId] -eq $true })

    if (@($foreignIdentities).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AGT-004-NO-FOREIGN-AGENT-IDENTITIES'
                Rationale          = 'No AgentIdentity entity was confirmed foreign in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($identity in $foreignIdentities) {
        $activeAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -SourceEntityId $identity.entityId
        $activeAssignments = @($activeAssignments | Where-Object { $_.assignmentState -eq 'Active' -and $tierZeroRoleIds -contains $_.targetEntityId })

        $evidenceRef = @([ordered]@{ entityId = $identity.entityId; entityType = 'AgentIdentity' })
        foreach ($assignment in $activeAssignments) {
            $evidenceRef += [ordered]@{ entityId = $assignment.targetEntityId; entityType = 'DirectoryRole' }
        }

        if (@($activeAssignments).Count -gt 0) {
            [ordered]@{
                Scope              = $identity.entityId
                Status             = 'Fail'
                ReasonCode         = 'AGT-004-FOREIGN-TIER-ZERO-ROLE'
                Rationale          = "Foreign agent identity '$($identity.displayName)' holds an Active assignment to a curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $identity.entityId
                Status             = 'Pass'
                ReasonCode         = 'AGT-004-NO-TIER-ZERO-ROLE'
                Rationale          = "Foreign agent identity '$($identity.displayName)' holds no Active assignment to any curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
