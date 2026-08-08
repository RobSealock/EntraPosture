#Requires -Version 7.4

function Test-EntraPostureForeignAgentUserAzureRoleControl {
    <#
        .SYNOPSIS
        AGT-012's evaluator: checks each foreign AgentUser for any AzureRoleAssignment.

        .DESCRIPTION
        Same transitive-foreign derivation as AGT-011's evaluator
        (Get-EntraPostureAgentUserForeignMap), correlated against AzureRoleAssignment.properties.
        principalId instead of a DirectoryRoleAssignment relationship -- the same
        entity-vs-relationship access-pattern distinction AGT-005's evaluator documents. Never
        produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        AGT-012.psd1's expectedResultSemantics.

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
    $foreignUsers = @($agentUsers | Where-Object { $foreignMap.Contains($_.entityId) -and $foreignMap[$_.entityId] -eq $true })

    if (@($foreignUsers).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AGT-012-NO-FOREIGN-AGENT-USERS'
                Rationale          = 'No AgentUser entity was confirmed foreign (via its parent agent identity) in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($agentUser in $foreignUsers) {
        $matchingAssignments = @($azureRoleAssignments | Where-Object { [string]$_.properties.principalId -eq $agentUser.entityId })

        $evidenceRef = @([ordered]@{ entityId = $agentUser.entityId; entityType = 'AgentUser' })
        foreach ($assignment in $matchingAssignments) {
            $evidenceRef += [ordered]@{ entityId = $assignment.entityId; entityType = 'AzureRoleAssignment' }
        }

        if (@($matchingAssignments).Count -gt 0) {
            [ordered]@{
                Scope              = $agentUser.entityId
                Status             = 'Fail'
                ReasonCode         = 'AGT-012-FOREIGN-AZURE-ROLE'
                Rationale          = "Foreign agent user '$($agentUser.displayName)' holds at least one Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $agentUser.entityId
                Status             = 'Pass'
                ReasonCode         = 'AGT-012-NO-AZURE-ROLE'
                Rationale          = "Foreign agent user '$($agentUser.displayName)' holds no Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
