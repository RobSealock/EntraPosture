#Requires -Version 7.4

function Test-EntraPostureTierZeroActivationJustificationControl {
    <#
        .SYNOPSIS
        PIM-004's evaluator: checks each curated Tier-0 role's PIM activation policy for whether
        it requires a business justification on self-activation.

        .DESCRIPTION
        Fixed-state, same curated Tier-0 role set as PIM-002/PIM-003. Never produces NotEvaluated
        or Error status -- assigned by the orchestration layer, per PIM-004.psd1's
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
                ReasonCode         = 'PIM-004-NO-TIER-ZERO-ROLES-ACTIVATED'
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

        $requiresJustification = @($assignment.properties.enabledRules) -contains 'Justification'

        $evidenceRef = @(
            [ordered]@{ entityId = $role.entityId; entityType = 'DirectoryRole' }
            [ordered]@{ entityId = $assignment.entityId; entityType = 'RoleManagementPolicyAssignment' }
        )

        if (-not $requiresJustification) {
            [ordered]@{
                Scope              = $role.entityId
                Status             = 'Fail'
                ReasonCode         = 'PIM-004-JUSTIFICATION-NOT-REQUIRED'
                Rationale          = "Tier-0 role '$($role.displayName)' does not require a business justification when an eligible user activates it."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope              = $role.entityId
                Status             = 'Pass'
                ReasonCode         = 'PIM-004-JUSTIFICATION-REQUIRED'
                Rationale          = "Tier-0 role '$($role.displayName)' requires a business justification on activation."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
