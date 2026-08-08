#Requires -Version 7.4

function Test-EntraPostureInternalAgentIdentityEntraRoleControl {
    <#
        .SYNOPSIS
        AGT-008's evaluator: checks each internal (non-foreign) AgentIdentity for an Active
        DirectoryRoleAssignment to a curated Tier-0 role.

        .DESCRIPTION
        Same correlation as AGT-004's evaluator (Test-EntraPostureForeignAgentIdentityEntraRoleControl),
        internal population, lower severity (2 vs 3) matching the matrix's own foreign-vs-internal
        severity split precedent (foreign = cross-tenant blast radius, higher) -- see AGT-008.psd1's
        own severity field. An AgentIdentity whose foreign-ness is unresolvable is excluded from
        this control's population entirely, the same reasoning AGT-004's evaluator documents.
        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        AGT-008.psd1's expectedResultSemantics.

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
    $internalIdentities = @($agentIdentities | Where-Object { $foreignMap.Contains($_.entityId) -and $foreignMap[$_.entityId] -eq $false })

    if (@($internalIdentities).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AGT-008-NO-INTERNAL-AGENT-IDENTITIES'
                Rationale          = 'No AgentIdentity entity was confirmed internal (non-foreign) in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($identity in $internalIdentities) {
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
                ReasonCode         = 'AGT-008-INTERNAL-TIER-ZERO-ROLE'
                Rationale          = "Internal agent identity '$($identity.displayName)' holds an Active assignment to a curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $identity.entityId
                Status             = 'Pass'
                ReasonCode         = 'AGT-008-NO-TIER-ZERO-ROLE'
                Rationale          = "Internal agent identity '$($identity.displayName)' holds no Active assignment to any curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
