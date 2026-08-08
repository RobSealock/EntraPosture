#Requires -Version 7.4

function Test-EntraPostureTierZeroActivationNotificationControl {
    <#
        .SYNOPSIS
        PIM-008's evaluator: checks each curated Tier-0 role's PIM policy for whether every
        activation-notification recipient path has been disabled.

        .DESCRIPTION
        Fixed-state, same curated Tier-0 role set as PIM-002 through PIM-007. Reads
        activationNotificationEnabled, the normalizer's own aggregate across every EndUser/
        Assignment-scoped NotificationRule (see NormalizeRoleManagementPolicyAssignment.ps1's own
        DESCRIPTION). Never produces NotEvaluated or Error status -- assigned by the orchestration
        layer, per PIM-008.psd1's expectedResultSemantics.

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

    if (@($tierZeroRoles).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'PIM-008-NO-TIER-ZERO-ROLES-ACTIVATED'
                Rationale          = 'None of the curated Tier-0 roles were present as DirectoryRole entities in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $policyAssignments = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'RoleManagementPolicyAssignment'

    $evaluationResults = @(foreach ($role in $tierZeroRoles) {
        $assignment = $policyAssignments | Where-Object { $_.properties.roleDefinitionId -eq $role.entityId } | Select-Object -First 1
        if (-not $assignment) { continue }

        $notificationsEnabled = [bool]$assignment.properties.activationNotificationEnabled

        $evidenceRef = @(
            [ordered]@{ entityId = $role.entityId; entityType = 'DirectoryRole' }
            [ordered]@{ entityId = $assignment.entityId; entityType = 'RoleManagementPolicyAssignment' }
        )

        if (-not $notificationsEnabled) {
            [ordered]@{
                Scope              = $role.entityId
                Status             = 'Fail'
                ReasonCode         = 'PIM-008-NOTIFICATIONS-DISABLED'
                Rationale          = "Tier-0 role '$($role.displayName)' has every activation-notification recipient path disabled."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $role.entityId
                Status             = 'Pass'
                ReasonCode         = 'PIM-008-NOTIFICATIONS-ENABLED'
                Rationale          = "Tier-0 role '$($role.displayName)' has at least one activation-notification recipient path enabled."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
