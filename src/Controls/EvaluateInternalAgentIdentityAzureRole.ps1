#Requires -Version 7.4

function Test-EntraPostureInternalAgentIdentityAzureRoleControl {
    <#
        .SYNOPSIS
        AGT-009's evaluator: checks each internal (non-foreign) AgentIdentity for any
        AzureRoleAssignment.

        .DESCRIPTION
        Same as AGT-005's evaluator (Test-EntraPostureForeignAgentIdentityAzureRoleControl),
        internal population. Never produces NotEvaluated or Error status -- assigned by the
        orchestration layer, per AGT-009.psd1's expectedResultSemantics.

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

    $azureRoleAssignments = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AzureRoleAssignment'

    $agentIdentities = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AgentIdentity'
    $foreignMap = Get-EntraPostureAgentIdentityForeignMap -EvidenceProvider $EvidenceProvider
    $internalIdentities = @($agentIdentities | Where-Object { $foreignMap.Contains($_.entityId) -and $foreignMap[$_.entityId] -eq $false })

    if (@($internalIdentities).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AGT-009-NO-INTERNAL-AGENT-IDENTITIES'
                Rationale          = 'No AgentIdentity entity was confirmed internal (non-foreign) in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($identity in $internalIdentities) {
        $matchingAssignments = @($azureRoleAssignments | Where-Object { [string]$_.properties.principalId -eq $identity.entityId })

        $evidenceRef = @([ordered]@{ entityId = $identity.entityId; entityType = 'AgentIdentity' })
        foreach ($assignment in $matchingAssignments) {
            $evidenceRef += [ordered]@{ entityId = $assignment.entityId; entityType = 'AzureRoleAssignment' }
        }

        if (@($matchingAssignments).Count -gt 0) {
            [ordered]@{
                Scope              = $identity.entityId
                Status             = 'Fail'
                ReasonCode         = 'AGT-009-INTERNAL-AZURE-ROLE'
                Rationale          = "Internal agent identity '$($identity.displayName)' holds at least one Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $identity.entityId
                Status             = 'Pass'
                ReasonCode         = 'AGT-009-NO-AZURE-ROLE'
                Rationale          = "Internal agent identity '$($identity.displayName)' holds no Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
