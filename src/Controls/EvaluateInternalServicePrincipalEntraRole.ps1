#Requires -Version 7.4

function Test-EntraPostureInternalServicePrincipalEntraRoleControl {
    <#
        .SYNOPSIS
        ENT-011's evaluator: checks each internal (non-foreign) ServicePrincipal entity for an
        Active DirectoryRoleAssignment to a curated Tier-0 role.

        .DESCRIPTION
        Same correlation as ENT-006's evaluator, internal population, lower severity matching
        the matrix's own foreign-vs-internal severity split precedent. Never produces
        NotEvaluated or Error status -- assigned by the orchestration layer, per ENT-011.psd1's
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

    $tierZeroRoleNames = @('Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator')

    $roles = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'DirectoryRole'
    $tierZeroRoleIds = @(@($roles | Where-Object { $tierZeroRoleNames -contains $_.displayName }) | ForEach-Object { $_.entityId })

    $servicePrincipals = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ServicePrincipal'
    $tenantScope = if (@($servicePrincipals).Count -gt 0) { $servicePrincipals[0].tenantScope } else { $null }
    $internalPrincipals = @($servicePrincipals | Where-Object {
        [string]::IsNullOrWhiteSpace([string]$_.properties.appOwnerOrganizationId) -or
        [string]$_.properties.appOwnerOrganizationId -eq $tenantScope
    })

    if (@($internalPrincipals).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'ENT-011-NO-INTERNAL-SERVICE-PRINCIPALS'
                Rationale = 'No ServicePrincipal entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($principal in $internalPrincipals) {
        $activeAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -SourceEntityId $principal.entityId
        $activeAssignments = @($activeAssignments | Where-Object { $_.assignmentState -eq 'Active' -and $tierZeroRoleIds -contains $_.targetEntityId })

        $evidenceRef = @([ordered]@{ entityId = $principal.entityId; entityType = 'ServicePrincipal' })
        foreach ($assignment in $activeAssignments) { $evidenceRef += [ordered]@{ entityId = $assignment.targetEntityId; entityType = 'DirectoryRole' } }

        if (@($activeAssignments).Count -gt 0) {
            [ordered]@{
                Scope = $principal.entityId; Status = 'Fail'; ReasonCode = 'ENT-011-INTERNAL-TIER-ZERO-ROLE'
                Rationale = "Internal service principal '$($principal.displayName)' holds an Active assignment to a curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $principal.entityId; Status = 'Pass'; ReasonCode = 'ENT-011-NO-TIER-ZERO-ROLE'
                Rationale = "Internal service principal '$($principal.displayName)' holds no Active assignment to any curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
