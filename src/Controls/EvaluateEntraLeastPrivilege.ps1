#Requires -Version 7.4

function Test-EntraPostureEntraLeastPrivilegeControl {
    <#
        .SYNOPSIS
        USR-006's evaluator: checks whether too many enabled users hold a curated Tier-0 Entra ID
        role, directly or through a role-assignable group's membership.

        .DESCRIPTION
        A single tenant-scoped result: Fail if 5 or more enabled users hold a curated Tier-0
        role (Global Administrator, Privileged Role Administrator, Privileged Authentication
        Administrator), Pass otherwise. The 5-user threshold is EntraFalcon's own lowest
        confidence boundary for this exact finding (re-derived from its publicly visible
        check_Tenant.psm1, not the source's own further graduated-confidence bands at 7/15/16+,
        which this project does not replicate -- a single fixed threshold matches this project's
        own per-control fixed-severity model, unlike that source's dynamic severity escalation).

        Group-held role assignments are expanded through TransitiveMemberOf to their user
        members -- the same relationship GRP-005's own evaluator already reads -- so a Tier-0
        role granted to a role-assignable group counts every enabled user transitively in that
        group, not just principals with a direct DirectoryRoleAssignment. A role held by a
        non-user principal (a service principal or agent identity) is not counted here --
        ENT-006/009/011 and AGT-004/008 already cover service-principal and agent-identity
        Tier-0 role holding as their own, separate findings. Never produces NotEvaluated or
        Error status -- assigned by the orchestration layer, per USR-006.psd1's
        expectedResultSemantics.

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

    $threshold = 5
    $tierZeroRoleNames = @('Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator')

    $roles = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'DirectoryRole'
    $tierZeroRoleIds = @(@($roles | Where-Object { $tierZeroRoleNames -contains $_.displayName }) | ForEach-Object { $_.entityId })

    $users = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'User'
    $enabledUserIds = @($users | Where-Object { $_.properties.accountEnabled -eq $true } | ForEach-Object { $_.entityId })
    $enabledUserIdSet = @{}
    foreach ($id in $enabledUserIds) { $enabledUserIdSet[$id] = $true }

    $tierZeroUserIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($roleId in $tierZeroRoleIds) {
        $assignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -TargetEntityId $roleId
        $activeAssignments = @($assignments | Where-Object { $_.assignmentState -eq 'Active' })

        foreach ($assignment in $activeAssignments) {
            $principalId = $assignment.sourceEntityId
            if ($enabledUserIdSet.ContainsKey($principalId)) {
                [void]$tierZeroUserIds.Add($principalId)
                continue
            }

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
            Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'USR-006-EXCESSIVE-TIER-ZERO-USERS'
            Rationale = "$count enabled users hold a curated Tier-0 Entra ID role (directly or through a role-assignable group), at or above the $threshold-user threshold."
            EvidenceReferences = @()
        }
    } else {
        [ordered]@{
            Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'USR-006-TIER-ZERO-USERS-WITHIN-RANGE'
            Rationale = "$count enabled users hold a curated Tier-0 Entra ID role (directly or through a role-assignable group), below the $threshold-user threshold."
            EvidenceReferences = @()
        }
    })

    return ,@($results)
}
