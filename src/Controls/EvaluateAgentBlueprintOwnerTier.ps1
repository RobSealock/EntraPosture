#Requires -Version 7.4

function Test-EntraPostureAgentBlueprintOwnerTierControl {
    <#
        .SYNOPSIS
        AGT-017's evaluator: for each AgentIdentityBlueprint, checks whether every owner holds a
        curated Tier-0 Entra ID role.

        .DESCRIPTION
        Inverse framing from every other AGT-* finding: Fails when a blueprint's owner set
        includes anyone who does NOT hold a curated Tier-0 role -- a blueprint able to mint
        privileged agent identities should itself be owned only by already-privileged,
        accountable principals. Correlates OwnerOf (owner -> blueprint, collected by
        CollectAgentIdentityBlueprints.ps1's owners N+1 fetch) against DirectoryRoleAssignment by
        principal ID, the same reuse pattern AGT-004's evaluator applies. Evaluated once per
        collected blueprint (not just blueprints with owners) -- a blueprint with zero owners is
        a real, distinct, per-blueprint outcome (AGT-017-NO-OWNERS), not folded into the overall
        tenant-scoped NotApplicable (which is reserved for "zero blueprints exist at all," the
        same NotApplicable scope AGT-001's evaluator uses). Never produces NotEvaluated or Error
        status -- assigned by the orchestration layer, per AGT-017.psd1's
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

    $blueprints = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AgentIdentityBlueprint'

    if (@($blueprints).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'AGT-017-NO-BLUEPRINTS'
                Rationale          = 'No AgentIdentityBlueprint entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($blueprint in $blueprints) {
        $owners = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'OwnerOf' -TargetEntityId $blueprint.entityId

        if (@($owners).Count -eq 0) {
            [ordered]@{
                Scope              = $blueprint.entityId
                Status             = 'NotApplicable'
                ReasonCode         = 'AGT-017-NO-OWNERS'
                Rationale          = "Agent identity blueprint '$($blueprint.displayName)' has no collected owner."
                EvidenceReferences = @([ordered]@{ entityId = $blueprint.entityId; entityType = 'AgentIdentityBlueprint' })
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

        $evidenceRef = @([ordered]@{ entityId = $blueprint.entityId; entityType = 'AgentIdentityBlueprint' })
        foreach ($ownerId in $nonTierZeroOwnerIds) {
            $evidenceRef += [ordered]@{ entityId = $ownerId; entityType = 'Unknown' }
        }

        if ($nonTierZeroOwnerIds.Count -gt 0) {
            [ordered]@{
                Scope              = $blueprint.entityId
                Status             = 'Fail'
                ReasonCode         = 'AGT-017-NON-TIER-ZERO-OWNER'
                Rationale          = "Agent identity blueprint '$($blueprint.displayName)' has at least one owner ($($nonTierZeroOwnerIds.Count) of $(@($owners).Count)) with no Active assignment to any curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $blueprint.entityId
                Status             = 'Pass'
                ReasonCode         = 'AGT-017-TIER-ZERO-OWNER-ONLY'
                Rationale          = "Agent identity blueprint '$($blueprint.displayName)' has every owner holding an Active assignment to a curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
