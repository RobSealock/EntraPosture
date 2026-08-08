#Requires -Version 7.4

function Test-EntraPostureTierZeroPermanentAssignmentControl {
    <#
        .SYNOPSIS
        PIM-005's evaluator: checks each curated Tier-0 role's PIM policy for whether an admin
        can create a permanent (non-expiring) direct active assignment.

        .DESCRIPTION
        Fixed-state, same curated Tier-0 role set as PIM-002/003/004. Reads
        adminAssignmentIsExpirationRequired specifically -- the Admin/Assignment-level expiration
        rule, not the EndUser/Assignment one PIM-003 reads (see
        NormalizeRoleManagementPolicyAssignment.ps1's own DESCRIPTION for why these are genuinely
        different settings, confirmed against Microsoft's own admin-UI documentation). Never
        produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        PIM-005.psd1's expectedResultSemantics.

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
                ReasonCode         = 'PIM-005-NO-TIER-ZERO-ROLES-ACTIVATED'
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

        $expirationRequired = [bool]$assignment.properties.adminAssignmentIsExpirationRequired

        $evidenceRef = @(
            [ordered]@{ entityId = $role.entityId; entityType = 'DirectoryRole' }
            [ordered]@{ entityId = $assignment.entityId; entityType = 'RoleManagementPolicyAssignment' }
        )

        if (-not $expirationRequired) {
            [ordered]@{
                Scope              = $role.entityId
                Status             = 'Fail'
                ReasonCode         = 'PIM-005-PERMANENT-ASSIGNMENT-ALLOWED'
                Rationale          = "Tier-0 role '$($role.displayName)' allows a directly-assigned active assignment with no expiration."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $role.entityId
                Status             = 'Pass'
                ReasonCode         = 'PIM-005-EXPIRATION-REQUIRED'
                Rationale          = "Tier-0 role '$($role.displayName)' requires an expiration on directly-assigned active assignments."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
