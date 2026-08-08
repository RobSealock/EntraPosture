#Requires -Version 7.4

function Test-EntraPostureAzureLeastPrivilegeControl {
    <#
        .SYNOPSIS
        USR-009's evaluator: checks whether too many enabled users hold a curated Tier-0 Azure
        RBAC role, directly or through a group's membership.

        .DESCRIPTION
        Same shape as USR-006 (its Entra ID sibling), applied to Azure RBAC instead:
        `AzureRoleAssignment.properties.roleDefinitionId` is ARM's own full resource ID
        (`/providers/Microsoft.Authorization/roleDefinitions/{guid}` or a subscription-scoped
        equivalent, confirmed directly against a live built-in role's own JSON representation,
        re-fetched 2026-08-08), not a bare GUID -- matched here by GUID suffix, case-insensitive,
        against `Get-EntraPostureTierZeroAzureRoleId`'s curated set
        (`TierZeroAzureRoleList.ps1`, this control's own reason for existing -- no Azure Tier-0
        role list existed in this project before it). A Group-typed principal is expanded through
        TransitiveMemberOf to its user members, the same "count once, deduplicated, direct or
        group-derived" correlation USR-006 already established -- Azure RBAC principalId for a
        Group-type assignment is the same Entra ID group object ID `TransitiveMemberOf`'s own
        targetEntityId already indexes.

        8-user threshold (not USR-006's 5) is EntraFalcon's own lowest confidence boundary for
        this specific finding, re-derived from its publicly visible check_Tenant.psm1 -- this
        project's own single fixed threshold, not that source's further graduated bands, matching
        every other control in this project's registry (including USR-006 itself).

        A role held by a non-user principal (a service principal or agent identity/managed
        identity) is not counted here -- ENT-007/012 and MAI-003/AGT-005/009/012 already cover
        service-principal/agent-identity/managed-identity Azure role holding as their own,
        separate findings. Never produces NotEvaluated or Error status -- assigned by the
        orchestration layer, per USR-009.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        Always exactly one element (tenant-scoped).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $threshold = 8
    $tierZeroAzureRoleIds = @(Get-EntraPostureTierZeroAzureRoleId)

    $azureRoleAssignments = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AzureRoleAssignment'
    $tierZeroAssignments = @($azureRoleAssignments | Where-Object {
        $roleDefinitionId = [string]$_.properties.roleDefinitionId
        if ([string]::IsNullOrWhiteSpace($roleDefinitionId)) { return $false }
        foreach ($tierZeroId in $tierZeroAzureRoleIds) {
            if ($roleDefinitionId.EndsWith($tierZeroId, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
    })

    $users = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'User'
    $enabledUserIds = @($users | Where-Object { $_.properties.accountEnabled -eq $true } | ForEach-Object { $_.entityId })
    $enabledUserIdSet = @{}
    foreach ($id in $enabledUserIds) { $enabledUserIdSet[$id] = $true }

    $tierZeroUserIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($assignment in $tierZeroAssignments) {
        $principalId = [string]$assignment.properties.principalId
        $principalType = [string]$assignment.properties.principalType

        if ($principalType -eq 'User' -and $enabledUserIdSet.ContainsKey($principalId)) {
            [void]$tierZeroUserIds.Add($principalId)
        } elseif ($principalType -eq 'Group') {
            $groupMembers = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'TransitiveMemberOf' -TargetEntityId $principalId
            foreach ($member in $groupMembers) {
                if ($enabledUserIdSet.ContainsKey($member.sourceEntityId)) {
                    [void]$tierZeroUserIds.Add($member.sourceEntityId)
                }
            }
        }
    }

    $count = $tierZeroUserIds.Count

    $results = @(if ($count -ge $threshold) {
        [ordered]@{
            Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'USR-009-EXCESSIVE-TIER-ZERO-USERS'
            Rationale = "$count enabled users hold a curated Tier-0 Azure RBAC role (directly or through a group), at or above the $threshold-user threshold."
            EvidenceReferences = @()
        }
    } else {
        [ordered]@{
            Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'USR-009-TIER-ZERO-USERS-WITHIN-RANGE'
            Rationale = "$count enabled users hold a curated Tier-0 Azure RBAC role (directly or through a group), below the $threshold-user threshold."
            EvidenceReferences = @()
        }
    })

    return ,@($results)
}
