#Requires -Version 7.4

function Test-EntraPostureStandingTierZeroAssignmentControl {
    <#
        .SYNOPSIS
        PIM-002's evaluator: for each Active DirectoryRoleAssignment targeting a curated Tier-0
        role, checks whether the same principal also has a PimEligible relationship for that
        role.

        .DESCRIPTION
        Relational and temporal (per PIM-002.psd1's category): correlates two independently
        collected relationship types (DirectoryRoleAssignment, PimEligible) keyed on the same
        principal+role pair -- PimEligible's targetEntityId (roleDefinitionId) and
        DirectoryRoleAssignment's targetEntityId (the DirectoryRole entity's own entityId,
        roleTemplateId) key against the same GUID space, per
        src/Normalization/NormalizePimEligibility.ps1's own documented rationale.

        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        PIM-002.psd1's expectedResultSemantics.

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

    # Curated Tier-0 set: each of these roles can reach Global Administrator-equivalent control
    # (Privileged Role Administrator can assign any role including Global Administrator;
    # Privileged Authentication Administrator can reset credentials for any admin, including
    # Global Administrators, unlike the non-privileged Authentication Administrator role). Not
    # independently re-verified against a live tenant this session -- see PIM-002.psd1's header
    # comment.
    $tierZeroRoleNames = @('Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator')

    $roles = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'DirectoryRole'
    $tierZeroRoles = @($roles | Where-Object { $tierZeroRoleNames -contains $_.displayName })

    if (@($tierZeroRoles).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'NotApplicable'
                ReasonCode         = 'PIM-002-NO-TIER-ZERO-ROLES-ACTIVATED'
                Rationale          = 'None of the curated Tier-0 roles were present as DirectoryRole entities in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($role in $tierZeroRoles) {
        $activeAssignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -TargetEntityId $role.entityId
        $activeAssignments = @($activeAssignments | Where-Object { $_.assignmentState -eq 'Active' })

        foreach ($assignment in $activeAssignments) {
            $principalId = $assignment.sourceEntityId
            # No @() wrapper around the call -- see EvaluateSensitiveGroupProtection.ps1's
            # identical comment for the full empirical writeup of why double-wrapping a
            # comma-protected return value at the call site silently produces a wrong Count.
            $eligibility = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'PimEligible' -SourceEntityId $principalId -TargetEntityId $role.entityId

            $evidenceRef = @(
                [ordered]@{ entityId = $role.entityId; entityType = 'DirectoryRole' }
                [ordered]@{ entityId = $principalId; entityType = 'User' }
            )

            if (@($eligibility).Count -eq 0) {
                [ordered]@{
                    Scope              = "$principalId::$($role.entityId)"
                    Status             = 'Fail'
                    ReasonCode         = 'PIM-002-STANDING-ASSIGNMENT-OUTSIDE-PIM'
                    Rationale          = "Principal $principalId holds an Active standing assignment to Tier-0 role '$($role.displayName)' with no corresponding PimEligible relationship -- the role is held permanently, not activated through PIM."
                    EvidenceReferences = $evidenceRef
                }
            } else {
                [ordered]@{
                    Scope              = "$principalId::$($role.entityId)"
                    Status             = 'Pass'
                    ReasonCode         = 'PIM-002-ASSIGNMENT-GOVERNED-BY-PIM'
                    Rationale          = "Principal $principalId's assignment to Tier-0 role '$($role.displayName)' has a corresponding PimEligible relationship."
                    EvidenceReferences = $evidenceRef
                }
            }
        }
    })

    return ,@($evaluationResults)
}
