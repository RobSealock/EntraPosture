#Requires -Version 7.4

function Test-EntraPostureForeignServicePrincipalAzureRoleControl {
    <#
        .SYNOPSIS
        ENT-007's evaluator: checks each foreign ServicePrincipal entity for any
        AzureRoleAssignment.

        .DESCRIPTION
        Same foreign derivation as ENT-006's evaluator (single-hop, appOwnerOrganizationId
        directly on ServicePrincipal), correlated against AzureRoleAssignment.properties.
        principalId instead of a DirectoryRoleAssignment relationship -- the same entity-vs-
        relationship distinction AGT-005's evaluator documents. Never produces NotEvaluated or
        Error status -- assigned by the orchestration layer, per ENT-007.psd1's
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
    $foreignPrincipals = @($servicePrincipals | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_.properties.appOwnerOrganizationId) -and
        [string]$_.properties.appOwnerOrganizationId -ne $tenantScope
    })

    if (@($foreignPrincipals).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'ENT-007-NO-FOREIGN-SERVICE-PRINCIPALS'
                Rationale = 'No ServicePrincipal entity was confirmed foreign in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($principal in $foreignPrincipals) {
        $matchingAssignments = @($azureRoleAssignments | Where-Object { [string]$_.properties.principalId -eq $principal.entityId })

        $evidenceRef = @([ordered]@{ entityId = $principal.entityId; entityType = 'ServicePrincipal' })
        foreach ($assignment in $matchingAssignments) { $evidenceRef += [ordered]@{ entityId = $assignment.entityId; entityType = 'AzureRoleAssignment' } }

        if (@($matchingAssignments).Count -gt 0) {
            [ordered]@{
                Scope = $principal.entityId; Status = 'Fail'; ReasonCode = 'ENT-007-FOREIGN-AZURE-ROLE'
                Rationale = "Foreign service principal '$($principal.displayName)' holds at least one Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $principal.entityId; Status = 'Pass'; ReasonCode = 'ENT-007-NO-AZURE-ROLE'
                Rationale = "Foreign service principal '$($principal.displayName)' holds no Azure RBAC role assignment."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
