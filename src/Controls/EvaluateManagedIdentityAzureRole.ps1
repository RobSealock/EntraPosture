#Requires -Version 7.4

function Test-EntraPostureManagedIdentityAzureRoleControl {
    <#
        .SYNOPSIS
        MAI-003's evaluator: checks each ManagedIdentity entity for any AzureRoleAssignment.

        .DESCRIPTION
        Same single-population shape as MAI-002's evaluator (no foreign/internal split for
        managed identities), correlated against AzureRoleAssignment.properties.principalId
        instead of a DirectoryRoleAssignment relationship -- the same entity-vs-relationship
        access-pattern distinction AGT-005's evaluator documents. Never produces NotEvaluated or
        Error status -- assigned by the orchestration layer, per MAI-003.psd1's
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
    $managedIdentities = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ManagedIdentity'

    if (@($managedIdentities).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'MAI-003-NO-MANAGED-IDENTITIES'
                Rationale = 'No ManagedIdentity entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($identity in $managedIdentities) {
        $matchingAssignments = @($azureRoleAssignments | Where-Object { [string]$_.properties.principalId -eq $identity.entityId })

        $evidenceRef = @([ordered]@{ entityId = $identity.entityId; entityType = 'ManagedIdentity' })
        foreach ($assignment in $matchingAssignments) { $evidenceRef += [ordered]@{ entityId = $assignment.entityId; entityType = 'AzureRoleAssignment' } }

        if (@($matchingAssignments).Count -gt 0) {
            [ordered]@{
                Scope = $identity.entityId; Status = 'Fail'; ReasonCode = 'MAI-003-AZURE-ROLE'
                Rationale = "Managed identity '$($identity.displayName)' holds at least one Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $identity.entityId; Status = 'Pass'; ReasonCode = 'MAI-003-NO-AZURE-ROLE'
                Rationale = "Managed identity '$($identity.displayName)' holds no Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
