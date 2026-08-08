#Requires -Version 7.4

function Test-EntraPostureManagedIdentityEntraRoleControl {
    <#
        .SYNOPSIS
        MAI-002's evaluator: checks each ManagedIdentity entity for an Active
        DirectoryRoleAssignment to a curated Tier-0 role.

        .DESCRIPTION
        Unlike the AGT-*/ENT-* foreign/internal split, managed identities have no "foreign"
        concept -- a managed identity is inherently scoped to the tenant it was created in, per
        Microsoft's own documented design, so this control has a single population, the same
        shape AGT-008's evaluator applies to internal agent identities. Zero new evidence: reuses
        the existing ServicePrincipal/ManagedIdentity entity domain (ManagedIdentity is the same
        Graph resource family, distinguished only by servicePrincipalType -- see
        ConvertTo-EntraPostureServicePrincipalEntity's own DESCRIPTION) and existing
        DirectoryRoleAssignment evidence. Never produces NotEvaluated or Error status -- assigned
        by the orchestration layer, per MAI-002.psd1's expectedResultSemantics.

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

    $managedIdentities = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ManagedIdentity'

    if (@($managedIdentities).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'MAI-002-NO-MANAGED-IDENTITIES'
                Rationale = 'No ManagedIdentity entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($identity in $managedIdentities) {
        $activeAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -SourceEntityId $identity.entityId
        $activeAssignments = @($activeAssignments | Where-Object { $_.assignmentState -eq 'Active' -and $tierZeroRoleIds -contains $_.targetEntityId })

        $evidenceRef = @([ordered]@{ entityId = $identity.entityId; entityType = 'ManagedIdentity' })
        foreach ($assignment in $activeAssignments) { $evidenceRef += [ordered]@{ entityId = $assignment.targetEntityId; entityType = 'DirectoryRole' } }

        if (@($activeAssignments).Count -gt 0) {
            [ordered]@{
                Scope = $identity.entityId; Status = 'Fail'; ReasonCode = 'MAI-002-TIER-ZERO-ROLE'
                Rationale = "Managed identity '$($identity.displayName)' holds an Active assignment to a curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $identity.entityId; Status = 'Pass'; ReasonCode = 'MAI-002-NO-TIER-ZERO-ROLE'
                Rationale = "Managed identity '$($identity.displayName)' holds no Active assignment to any curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
