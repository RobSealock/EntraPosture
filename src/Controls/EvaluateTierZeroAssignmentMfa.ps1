#Requires -Version 7.4

function Test-EntraPostureTierZeroAssignmentMfaControl {
    <#
        .SYNOPSIS
        PIM-007's evaluator: checks each curated Tier-0 role's PIM policy for whether a direct
        admin-created active assignment requires multifactor authentication.

        .DESCRIPTION
        Fixed-state, same curated Tier-0 role set as PIM-002/003/004/005/006. Reads
        adminAssignmentEnabledRules specifically -- the Admin/Assignment-level enablement rule,
        the only point Microsoft's own documentation confirms PIM can actually enforce MFA for a
        direct assignment (see PIM-007.psd1's own rationale for the direct quote). Never produces
        NotEvaluated or Error status -- assigned by the orchestration layer, per PIM-007.psd1's
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
    $tierZeroRoles = @($roles | Where-Object { $tierZeroRoleNames -contains $_.displayName })

    if (@($tierZeroRoles).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'PIM-007-NO-TIER-ZERO-ROLES-ACTIVATED'
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

        $requiresMfa = @($assignment.properties.adminAssignmentEnabledRules) -contains 'MultiFactorAuthentication'

        $evidenceRef = @(
            [ordered]@{ entityId = $role.entityId; entityType = 'DirectoryRole' }
            [ordered]@{ entityId = $assignment.entityId; entityType = 'RoleManagementPolicyAssignment' }
        )

        if (-not $requiresMfa) {
            [ordered]@{
                Scope              = $role.entityId
                Status             = 'Fail'
                ReasonCode         = 'PIM-007-MFA-NOT-REQUIRED'
                Rationale          = "Tier-0 role '$($role.displayName)' does not require multifactor authentication when an admin creates a direct active assignment."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $role.entityId
                Status             = 'Pass'
                ReasonCode         = 'PIM-007-MFA-REQUIRED'
                Rationale          = "Tier-0 role '$($role.displayName)' requires multifactor authentication on direct active assignment."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
