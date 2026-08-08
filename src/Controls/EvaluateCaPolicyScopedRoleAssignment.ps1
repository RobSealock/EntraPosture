#Requires -Version 7.4

function Test-EntraPostureCaPolicyScopedRoleAssignmentControl {
    <#
        .SYNOPSIS
        CAP-011's evaluator: for each enabled Conditional Access policy whose
        conditions.users.includeRoles names at least one role, checks whether any of those roles
        has an administrative-unit-scoped assignment -- a holder Conditional Access role targeting
        silently does not cover.

        .DESCRIPTION
        Microsoft's own documentation states this precisely: "Conditional Access policies don't
        support users assigned a directory role scoped to an administrative unit or directory
        roles scoped directly to an object, like through custom roles" (confirmed live
        2026-08-08, concept-conditional-access-users-groups.md). A policy built to, for example,
        require phishing-resistant MFA for every Global Administrator silently fails to protect a
        Global Administrator whose own assignment happens to be administrative-unit-scoped -- CA
        role-based targeting only ever matches tenant-wide assignments. RoleAssignmentScope
        evidence (this control's own reason for existing -- see
        CollectRoleAssignmentScopes.ps1's own DESCRIPTION for why the existing
        DirectoryRoleAssignment evidence can't answer this) is matched against a policy's
        includeRoles by roleDefinitionId, the same roleTemplateId GUID space DirectoryRole's own
        entityId already uses (confirmed via NormalizeDirectoryRole.ps1's own choice of
        roleTemplateId as its stable entityId). A role in includeRoles with zero current
        assignments at all cannot be "gapped" (there's no uncovered holder to miss) and does not
        by itself fail the policy. Never produces NotEvaluated or Error status -- assigned by the
        orchestration layer, per CAP-011.psd1's expectedResultSemantics.

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

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ConditionalAccessPolicy'
    $enabledPolicies = @($policies | Where-Object { $_.properties.state -eq 'enabled' })
    $roleScopedPolicies = @($enabledPolicies | Where-Object { @($_.properties.conditions.users.includeRoles).Count -gt 0 })

    if (@($roleScopedPolicies).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'CAP-011-NO-ROLE-SCOPED-POLICIES'
                Rationale = 'No enabled Conditional Access policy names any role in its own users.includeRoles condition.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($policy in $roleScopedPolicies) {
        $includedRoleIds = @($policy.properties.conditions.users.includeRoles)
        $gappedRoleIds = [System.Collections.Generic.List[string]]::new()
        $evidenceRef = @([ordered]@{ entityId = $policy.entityId; entityType = 'ConditionalAccessPolicy' })

        foreach ($roleId in $includedRoleIds) {
            $scopeRelationships = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'RoleAssignmentScope' -TargetEntityId $roleId
            $auScopedAssignments = @($scopeRelationships | Where-Object { $_.scope -eq 'administrativeUnit' })
            if (@($auScopedAssignments).Count -gt 0) {
                $gappedRoleIds.Add($roleId)
                $evidenceRef += [ordered]@{ entityId = $roleId; entityType = 'DirectoryRole' }
            }
        }

        if ($gappedRoleIds.Count -gt 0) {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Fail'; ReasonCode = 'CAP-011-SCOPED-ASSIGNMENT-GAP'
                Rationale = "Conditional Access policy '$($policy.displayName)' includes $($gappedRoleIds.Count) role(s) with at least one administrative-unit-scoped assignment -- Conditional Access role targeting does not cover those holders."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Pass'; ReasonCode = 'CAP-011-NO-SCOPED-ASSIGNMENT-GAP'
                Rationale = "Conditional Access policy '$($policy.displayName)' includes no role with an administrative-unit-scoped assignment."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
