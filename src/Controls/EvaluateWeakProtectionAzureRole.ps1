#Requires -Version 7.4

function Test-EntraPostureWeakProtectionAzureRoleControl {
    <#
        .SYNOPSIS
        USR-011's evaluator: checks each enabled user holding a curated Tier-0 Azure RBAC role
        (directly or through a group) for whether their registered authentication methods are
        passwordless-capable.

        .DESCRIPTION
        Azure RBAC sibling of USR-010 -- same "weak" definition
        (`isPasswordlessCapable -ne $true` on UserRegistrationDetails, see USR-010's own
        DESCRIPTION for why this is the citable line drawn instead of self-curated
        methodsRegistered string matching), applied to the curated Tier-0 Azure role list
        (`TierZeroAzureRoleList.ps1`, USR-009's own list, GUID-suffix matched against
        AzureRoleAssignment.properties.roleDefinitionId) and the same direct-or-group-transitive
        correlation USR-009 already established. Never produces NotEvaluated or Error status --
        assigned by the orchestration layer, per USR-011.psd1's expectedResultSemantics.

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
    $enabledUserById = @{}
    foreach ($user in $users) {
        if ($user.properties.accountEnabled -eq $true) { $enabledUserById[$user.entityId] = $user }
    }

    $tierZeroUserIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($assignment in $tierZeroAssignments) {
        $principalId = [string]$assignment.properties.principalId
        $principalType = [string]$assignment.properties.principalType

        if ($principalType -eq 'User' -and $enabledUserById.ContainsKey($principalId)) {
            [void]$tierZeroUserIds.Add($principalId)
        } elseif ($principalType -eq 'Group') {
            $groupMembers = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'TransitiveMemberOf' -TargetEntityId $principalId
            foreach ($member in $groupMembers) {
                if ($enabledUserById.ContainsKey($member.sourceEntityId)) {
                    [void]$tierZeroUserIds.Add($member.sourceEntityId)
                }
            }
        }
    }

    if ($tierZeroUserIds.Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'USR-011-NO-TIER-ZERO-USERS'
                Rationale = 'No enabled user holds a curated Tier-0 Azure RBAC role, directly or through a group.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $registrationDetails = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'UserRegistrationDetails'
    $registrationById = @{}
    foreach ($record in $registrationDetails) { $registrationById[$record.entityId] = $record }

    $evaluationResults = @(foreach ($userId in $tierZeroUserIds) {
        $user = $enabledUserById[$userId]
        $evidenceRef = @([ordered]@{ entityId = $userId; entityType = 'User' })

        if (-not $registrationById.ContainsKey($userId)) {
            [ordered]@{
                Scope = $userId; Status = 'Fail'; ReasonCode = 'USR-011-NO-REGISTRATION-EVIDENCE'
                Rationale = "Tier-0 Azure role holder '$($user.displayName)' has no UserRegistrationDetails record in the collected evidence."
                EvidenceReferences = $evidenceRef
            }
            continue
        }

        $registration = $registrationById[$userId]
        $evidenceRef += [ordered]@{ entityId = $userId; entityType = 'UserRegistrationDetails' }

        if ($registration.properties.isPasswordlessCapable -eq $true) {
            [ordered]@{
                Scope = $userId; Status = 'Pass'; ReasonCode = 'USR-011-PASSWORDLESS-CAPABLE'
                Rationale = "Tier-0 Azure role holder '$($user.displayName)' has registered a passwordless-capable strong authentication method."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $userId; Status = 'Fail'; ReasonCode = 'USR-011-NOT-PASSWORDLESS-CAPABLE'
                Rationale = "Tier-0 Azure role holder '$($user.displayName)' has not registered a passwordless-capable strong authentication method."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
