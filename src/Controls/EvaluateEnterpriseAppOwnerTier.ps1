#Requires -Version 7.4

function Test-EntraPostureEnterpriseAppOwnerTierControl {
    <#
        .SYNOPSIS
        ENT-003's evaluator: for each ServicePrincipal, checks whether every owner holds a
        curated Tier-0 Entra ID role.

        .DESCRIPTION
        Same inverse framing and correlation pattern as AGT-017's evaluator
        (Test-EntraPostureAgentBlueprintOwnerTierControl), generalized from AgentIdentityBlueprint
        to every ordinary ServicePrincipal -- an enterprise application able to be modified or
        extended by an owner should itself be owned only by already-privileged, accountable
        principals. Correlates OwnerOf (owner -> service principal, collected by
        CollectServicePrincipals.ps1's owners N+1 fetch) against DirectoryRoleAssignment by
        principal ID. Evaluated once per collected ServicePrincipal entity (not just those with
        owners, and not restricted to ManagedIdentity -- a managed identity has no owner concept
        in Graph, so it will always land in the NO-OWNERS branch rather than being filtered out
        up front, matching how EF-EAP-007's own EntraFalcon precedent applies uniformly to the
        whole service principal population). Never produces NotEvaluated or Error status --
        assigned by the orchestration layer, per ENT-003.psd1's expectedResultSemantics.

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

    if (@($servicePrincipals).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'ENT-003-NO-SERVICE-PRINCIPALS'
                Rationale          = 'No ServicePrincipal entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($sp in $servicePrincipals) {
        $owners = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'OwnerOf' -TargetEntityId $sp.entityId

        if (@($owners).Count -eq 0) {
            [ordered]@{
                Scope              = $sp.entityId
                Status             = 'NotApplicable'
                ReasonCode         = 'ENT-003-NO-OWNERS'
                Rationale          = "Service principal '$($sp.displayName)' has no collected owner."
                EvidenceReferences = @([ordered]@{ entityId = $sp.entityId; entityType = 'ServicePrincipal' })
            }
            continue
        }

        $nonTierZeroOwnerIds = [System.Collections.Generic.List[string]]::new()
        foreach ($owner in $owners) {
            $ownerActiveTierZeroAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -SourceEntityId $owner.sourceEntityId
            $ownerActiveTierZeroAssignments = @($ownerActiveTierZeroAssignments | Where-Object { $_.assignmentState -eq 'Active' -and $tierZeroRoleIds -contains $_.targetEntityId })
            if (@($ownerActiveTierZeroAssignments).Count -eq 0) {
                $nonTierZeroOwnerIds.Add($owner.sourceEntityId)
            }
        }

        $evidenceRef = @([ordered]@{ entityId = $sp.entityId; entityType = 'ServicePrincipal' })
        foreach ($ownerId in $nonTierZeroOwnerIds) {
            $evidenceRef += [ordered]@{ entityId = $ownerId; entityType = 'Unknown' }
        }

        if ($nonTierZeroOwnerIds.Count -gt 0) {
            [ordered]@{
                Scope              = $sp.entityId
                Status             = 'Fail'
                ReasonCode         = 'ENT-003-NON-TIER-ZERO-OWNER'
                Rationale          = "Service principal '$($sp.displayName)' has at least one owner ($($nonTierZeroOwnerIds.Count) of $(@($owners).Count)) with no Active assignment to any curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $sp.entityId
                Status             = 'Pass'
                ReasonCode         = 'ENT-003-TIER-ZERO-OWNER-ONLY'
                Rationale          = "Service principal '$($sp.displayName)' has every owner holding an Active assignment to a curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
