#Requires -Version 7.4

function Test-EntraPostureHybridUserAzureRoleControl {
    <#
        .SYNOPSIS
        USR-008's evaluator: checks each hybrid-synced User entity for any AzureRoleAssignment.

        .DESCRIPTION
        Same concern as USR-007's evaluator, applied to the Azure RBAC authorization plane.
        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        USR-008.psd1's expectedResultSemantics.

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

    $users = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'User'
    $hybridUsers = @($users | Where-Object { [bool]$_.properties.onPremisesSyncEnabled })

    if (@($hybridUsers).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'USR-008-NO-HYBRID-USERS'
                Rationale = 'No User entity with onPremisesSyncEnabled=true was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($user in $hybridUsers) {
        $matchingAssignments = @($azureRoleAssignments | Where-Object { [string]$_.properties.principalId -eq $user.entityId })

        $evidenceRef = @([ordered]@{ entityId = $user.entityId; entityType = 'User' })
        foreach ($assignment in $matchingAssignments) { $evidenceRef += [ordered]@{ entityId = $assignment.entityId; entityType = 'AzureRoleAssignment' } }

        if (@($matchingAssignments).Count -gt 0) {
            [ordered]@{
                Scope = $user.entityId; Status = 'Fail'; ReasonCode = 'USR-008-HYBRID-AZURE-ROLE'
                Rationale = "Hybrid-synced user '$($user.displayName)' holds at least one Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $user.entityId; Status = 'Pass'; ReasonCode = 'USR-008-NO-AZURE-ROLE'
                Rationale = "Hybrid-synced user '$($user.displayName)' holds no Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
