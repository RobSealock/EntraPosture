#Requires -Version 7.4

function Test-EntraPostureWeakProtectionEntraRoleControl {
    <#
        .SYNOPSIS
        USR-010's evaluator: checks each enabled user holding a curated Tier-0 Entra ID role
        (directly or through a role-assignable group) for whether their registered
        authentication methods are passwordless-capable.

        .DESCRIPTION
        "Weak protection" is defined here as `isPasswordlessCapable -ne $true` on that user's
        own UserRegistrationDetails record -- a field Microsoft's own resource page defines
        precisely: "Indicates whether the user has registered a passwordless strong
        authentication method (including FIDO2, Windows Hello for Business, and Microsoft
        Authenticator (Passwordless)) that is allowed by the authentication methods policy"
        (confirmed live 2026-08-08). Deliberately not string-matching methodsRegistered against a
        self-curated "phishing-resistant method" list -- Microsoft's own userRegistrationDetails
        reference page documents methodsRegistered only as "such as mobilePhone, email,
        passKeyDeviceBound" (no closed, citable enum), so isPasswordlessCapable is the most
        precise, fully Microsoft-computed signal available, not a proxy this project would need
        to independently re-derive and risk getting wrong. It is a deliberately broader definition
        of "weak" than the built-in Phishing-resistant MFA strength (which also excludes
        Authenticator Passwordless) -- documented here as the citable, defensible line this
        control draws, not a claim of exact equivalence to that narrower Conditional Access
        concept. A Tier-0 user with `isMfaRegistered -eq $false` also fails here (no passwordless
        method registered at all is the strongest form of "not passwordless-capable") -- this
        necessarily overlaps with USR-012 (no MFA factors registered, population-wide) for that
        subset of users, the same kind of intentional overlap this project already accepts
        between USR-006/USR-007 (least-privilege count vs. hybrid-user Tier-0 holding). A Tier-0
        user with no matching UserRegistrationDetails record at all (evidence collected, but this
        specific user absent from the returned set) also fails -- "missing evidence never becomes
        a clean result," this project's standing principle. Tier-0 role list (Global
        Administrator, Privileged Role Administrator, Privileged Authentication Administrator)
        and the direct-or-group-transitive correlation are identical to USR-006/USR-007's own.
        Never produces NotEvaluated or Error status -- assigned by the orchestration layer, per
        USR-010.psd1's expectedResultSemantics.

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
    $tierZeroRoleIds = @(@($roles | Where-Object { $tierZeroRoleNames -contains $_.displayName }) | ForEach-Object { $_.entityId })

    $users = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'User'
    $enabledUserById = @{}
    foreach ($user in $users) {
        if ($user.properties.accountEnabled -eq $true) { $enabledUserById[$user.entityId] = $user }
    }

    $tierZeroUserIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($roleId in $tierZeroRoleIds) {
        $assignments = Get-EntraPostureRelationship -Provider $EvidenceProvider -RelationshipType 'DirectoryRoleAssignment' -TargetEntityId $roleId
        $activeAssignments = @($assignments | Where-Object { $_.assignmentState -eq 'Active' })

        foreach ($assignment in $activeAssignments) {
            $principalId = $assignment.sourceEntityId
            if ($enabledUserById.ContainsKey($principalId)) {
                [void]$tierZeroUserIds.Add($principalId)
                continue
            }

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
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'USR-010-NO-TIER-ZERO-USERS'
                Rationale = 'No enabled user holds a curated Tier-0 Entra ID role, directly or through a role-assignable group.'
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
                Scope = $userId; Status = 'Fail'; ReasonCode = 'USR-010-NO-REGISTRATION-EVIDENCE'
                Rationale = "Tier-0 role holder '$($user.displayName)' has no UserRegistrationDetails record in the collected evidence."
                EvidenceReferences = $evidenceRef
            }
            continue
        }

        $registration = $registrationById[$userId]
        $evidenceRef += [ordered]@{ entityId = $userId; entityType = 'UserRegistrationDetails' }

        if ($registration.properties.isPasswordlessCapable -eq $true) {
            [ordered]@{
                Scope = $userId; Status = 'Pass'; ReasonCode = 'USR-010-PASSWORDLESS-CAPABLE'
                Rationale = "Tier-0 role holder '$($user.displayName)' has registered a passwordless-capable strong authentication method."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $userId; Status = 'Fail'; ReasonCode = 'USR-010-NOT-PASSWORDLESS-CAPABLE'
                Rationale = "Tier-0 role holder '$($user.displayName)' has not registered a passwordless-capable strong authentication method."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
