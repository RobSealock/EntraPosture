#Requires -Version 7.4

function Test-EntraPostureHybridUserEntraRoleControl {
    <#
        .SYNOPSIS
        USR-007's evaluator: checks each hybrid-synced User entity (onPremisesSyncEnabled) for
        an Active DirectoryRoleAssignment to a curated Tier-0 role.

        .DESCRIPTION
        A Tier-0 role held by an account synced from on-premises Active Directory means an
        on-prem compromise (a materially larger, harder-to-fully-secure attack surface than
        cloud-only identity) can reach cloud Tier-0 privilege -- the same concern Microsoft's own
        hybrid-identity security guidance names directly. Never produces NotEvaluated or Error
        status -- assigned by the orchestration layer, per USR-007.psd1's
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

    $users = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'User'
    $hybridUsers = @($users | Where-Object { [bool]$_.properties.onPremisesSyncEnabled })

    if (@($hybridUsers).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'USR-007-NO-HYBRID-USERS'
                Rationale = 'No User entity with onPremisesSyncEnabled=true was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($user in $hybridUsers) {
        $activeAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -SourceEntityId $user.entityId
        $activeAssignments = @($activeAssignments | Where-Object { $_.assignmentState -eq 'Active' -and $tierZeroRoleIds -contains $_.targetEntityId })

        $evidenceRef = @([ordered]@{ entityId = $user.entityId; entityType = 'User' })
        foreach ($assignment in $activeAssignments) { $evidenceRef += [ordered]@{ entityId = $assignment.targetEntityId; entityType = 'DirectoryRole' } }

        if (@($activeAssignments).Count -gt 0) {
            [ordered]@{
                Scope = $user.entityId; Status = 'Fail'; ReasonCode = 'USR-007-HYBRID-TIER-ZERO-ROLE'
                Rationale = "Hybrid-synced user '$($user.displayName)' holds an Active assignment to a curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $user.entityId; Status = 'Pass'; ReasonCode = 'USR-007-NO-TIER-ZERO-ROLE'
                Rationale = "Hybrid-synced user '$($user.displayName)' holds no Active assignment to any curated Tier-0 Entra ID role."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
