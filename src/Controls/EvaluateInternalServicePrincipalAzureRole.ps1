#Requires -Version 7.4

function Test-EntraPostureInternalServicePrincipalAzureRoleControl {
    <#
        .SYNOPSIS
        ENT-012's evaluator: checks each internal (non-foreign) ServicePrincipal entity for any
        AzureRoleAssignment.

        .DESCRIPTION
        Same as ENT-007's evaluator, internal population. Never produces NotEvaluated or Error
        status -- assigned by the orchestration layer, per ENT-012.psd1's
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

    $servicePrincipals = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ServicePrincipal'
    $tenantScope = if (@($servicePrincipals).Count -gt 0) { $servicePrincipals[0].tenantScope } else { $null }
    $internalPrincipals = @($servicePrincipals | Where-Object {
        [string]::IsNullOrWhiteSpace([string]$_.properties.appOwnerOrganizationId) -or
        [string]$_.properties.appOwnerOrganizationId -eq $tenantScope
    })

    if (@($internalPrincipals).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'ENT-012-NO-INTERNAL-SERVICE-PRINCIPALS'
                Rationale = 'No ServicePrincipal entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($principal in $internalPrincipals) {
        $matchingAssignments = @($azureRoleAssignments | Where-Object { [string]$_.properties.principalId -eq $principal.entityId })

        $evidenceRef = @([ordered]@{ entityId = $principal.entityId; entityType = 'ServicePrincipal' })
        foreach ($assignment in $matchingAssignments) { $evidenceRef += [ordered]@{ entityId = $assignment.entityId; entityType = 'AzureRoleAssignment' } }

        if (@($matchingAssignments).Count -gt 0) {
            [ordered]@{
                Scope = $principal.entityId; Status = 'Fail'; ReasonCode = 'ENT-012-INTERNAL-AZURE-ROLE'
                Rationale = "Internal service principal '$($principal.displayName)' holds at least one Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $principal.entityId; Status = 'Pass'; ReasonCode = 'ENT-012-NO-AZURE-ROLE'
                Rationale = "Internal service principal '$($principal.displayName)' holds no Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
