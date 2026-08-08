#Requires -Version 7.4

function Test-EntraPostureTierZeroAuthContextOrApprovalControl {
    <#
        .SYNOPSIS
        PIM-009's evaluator: checks each curated Tier-0 role's PIM activation policy for whether
        it requires at least one of an authentication context or approval.

        .DESCRIPTION
        Fixed-state, same curated Tier-0 role set as PIM-002 through PIM-008. Deliberately does
        not judge whether a configured authentication context is actually functional -- that is
        AUTHCTX-001/002's job (build order item 7), which this control's own psd1 provenance notes
        name explicitly. Never produces NotEvaluated or Error status -- assigned by the
        orchestration layer, per PIM-009.psd1's expectedResultSemantics.

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
                ReasonCode         = 'PIM-009-NO-TIER-ZERO-ROLES-ACTIVATED'
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

        $authContextEnabled = [bool]$assignment.properties.authenticationContextEnabled
        $approvalRequired = [bool]$assignment.properties.approvalRequired
        $atLeastOne = $authContextEnabled -or $approvalRequired

        $evidenceRef = @(
            [ordered]@{ entityId = $role.entityId; entityType = 'DirectoryRole' }
            [ordered]@{ entityId = $assignment.entityId; entityType = 'RoleManagementPolicyAssignment' }
        )

        if (-not $atLeastOne) {
            [ordered]@{
                Scope              = $role.entityId
                Status             = 'Fail'
                ReasonCode         = 'PIM-009-NEITHER-CONFIGURED'
                Rationale          = "Tier-0 role '$($role.displayName)' requires neither an authentication context nor approval on activation."
                EvidenceReferences = $evidenceRef
            }
        } else {
            $configured = @(if ($authContextEnabled) { 'authentication context' }; if ($approvalRequired) { 'approval' }) -join ' and '
            [ordered]@{
                Scope              = $role.entityId
                Status             = 'Pass'
                ReasonCode         = 'PIM-009-AT-LEAST-ONE-CONFIGURED'
                Rationale          = "Tier-0 role '$($role.displayName)' requires $configured on activation."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
