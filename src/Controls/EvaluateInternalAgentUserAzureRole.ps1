#Requires -Version 7.4

function Test-EntraPostureInternalAgentUserAzureRoleControl {
    <#
        .SYNOPSIS
        AGT-014's evaluator: checks each internal (non-foreign) AgentUser entity for any
        AzureRoleAssignment.

        .DESCRIPTION
        Same "defensive check despite unresolved reachability" reasoning as AGT-013's evaluator
        -- see that file's own DESCRIPTION. Correlated against AzureRoleAssignment.properties.
        principalId instead of a DirectoryRoleAssignment relationship, the same entity-vs-
        relationship distinction AGT-005/012's evaluators document. Never produces NotEvaluated
        or Error status -- assigned by the orchestration layer, per AGT-014.psd1's
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

    $azureRoleAssignments = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AzureRoleAssignment'

    $agentUsers = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AgentUser'
    $foreignMap = Get-EntraPostureAgentUserForeignMap -EvidenceProvider $EvidenceProvider
    $internalUsers = @($agentUsers | Where-Object { $foreignMap.Contains($_.entityId) -and $foreignMap[$_.entityId] -eq $false })

    if (@($internalUsers).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'AGT-014-NO-INTERNAL-AGENT-USERS'
                Rationale = 'No AgentUser entity was confirmed internal (non-foreign, via its parent agent identity) in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($agentUser in $internalUsers) {
        $matchingAssignments = @($azureRoleAssignments | Where-Object { [string]$_.properties.principalId -eq $agentUser.entityId })

        $evidenceRef = @([ordered]@{ entityId = $agentUser.entityId; entityType = 'AgentUser' })
        foreach ($assignment in $matchingAssignments) { $evidenceRef += [ordered]@{ entityId = $assignment.entityId; entityType = 'AzureRoleAssignment' } }

        if (@($matchingAssignments).Count -gt 0) {
            [ordered]@{
                Scope = $agentUser.entityId; Status = 'Fail'; ReasonCode = 'AGT-014-INTERNAL-AZURE-ROLE'
                Rationale = "Internal agent user '$($agentUser.displayName)' holds at least one Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $agentUser.entityId; Status = 'Pass'; ReasonCode = 'AGT-014-NO-AZURE-ROLE'
                Rationale = "Internal agent user '$($agentUser.displayName)' holds no Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
