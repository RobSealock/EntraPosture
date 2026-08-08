#Requires -Version 7.4

function Test-EntraPostureTierZeroRoleCaCoverageControl {
    <#
        .SYNOPSIS
        CAP-010's evaluator: for each curated Tier-0 role with at least one Active
        DirectoryRoleAssignment, checks whether any enabled Conditional Access policy's
        `conditions.users.includeRoles` names that role.

        .DESCRIPTION
        Scoped to the same curated Tier-0 role set (Global Administrator, Privileged Role
        Administrator, Privileged Authentication Administrator) every PIM-00x/CA-002/AGT-*
        control in this registry already reuses -- the source finding's own "Tier-0/Tier-1"
        framing is narrowed to Tier-0 only here, since this project has never independently
        curated a "Tier-1" role set (a real, deliberate scope narrowing, stated as such rather
        than silently assumed equivalent). Distinct from CA-001 (which checks per-scenario
        *effective* MFA coverage for Global Administrator specifically): this is the coarser
        "is this role named in any policy's role condition at all" precursor check, across the
        full curated set. Never produces NotEvaluated or Error status -- assigned by the
        orchestration layer, per CAP-010.psd1's expectedResultSemantics.

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
    $tierZeroRoles = @($roles | Where-Object { $tierZeroRoleNames -contains $_.displayName })

    $activeTierZeroRoles = @(foreach ($role in $tierZeroRoles) {
        $activeAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -TargetEntityId $role.entityId
        if (@($activeAssignments | Where-Object { $_.assignmentState -eq 'Active' }).Count -gt 0) { $role }
    })

    if (@($activeTierZeroRoles).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'CAP-010-NO-TIER-ZERO-ROLES-ACTIVATED'
                Rationale = 'None of the curated Tier-0 roles have any Active assignment in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ConditionalAccessPolicy'
    $enabledPolicies = @($policies | Where-Object { $_.properties.state -eq 'enabled' })

    $evaluationResults = @(foreach ($role in $activeTierZeroRoles) {
        $coveringPolicies = @($enabledPolicies | Where-Object { @($_.properties.conditions.users.includeRoles) -contains $role.entityId })

        $evidenceRef = @([ordered]@{ entityId = $role.entityId; entityType = 'DirectoryRole' })
        foreach ($p in $coveringPolicies) { $evidenceRef += [ordered]@{ entityId = $p.entityId; entityType = 'ConditionalAccessPolicy' } }

        if (@($coveringPolicies).Count -gt 0) {
            [ordered]@{
                Scope = $role.entityId; Status = 'Pass'; ReasonCode = 'CAP-010-ROLE-COVERED'
                Rationale = "Tier-0 role '$($role.displayName)' is named in at least one enabled Conditional Access policy's role condition."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $role.entityId; Status = 'Fail'; ReasonCode = 'CAP-010-ROLE-NOT-COVERED'
                Rationale = "Tier-0 role '$($role.displayName)' has an Active assignment but is not named in any enabled Conditional Access policy's role condition."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
