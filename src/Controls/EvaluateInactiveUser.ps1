#Requires -Version 7.4

function Test-EntraPostureInactiveUserControl {
    <#
        .SYNOPSIS
        USR-005's evaluator: for each User, checks whether it has been inactive for at least 180
        days.

        .DESCRIPTION
        Inactivity is judged primarily from the correlated UserSignInActivity entity's
        lastSuccessfulSignInDateTime (the field Microsoft's own signInActivity resource reference
        page recommends specifically "to build reports, such as inactive users"), falling back to
        the User entity's own createdDateTime when the user has never successfully signed in at
        all (no lastSuccessfulSignInDateTime recorded) -- the same two-signal shape EntraFalcon's
        own check_Users.psm1 uses for this exact finding (re-derived independently from its
        publicly visible source, not ported: `$InactiveDays_lastsuccessfulSignin -ge 180 -or
        ($InactiveDays_lastsuccessfulSignin -eq "-" -and $CreatedDays -gt 180)`, 180 days both
        branches). This project's own re-derivation deliberately does not replicate that source's
        further "Cloud Sync service account" exemption (a narrow, brittle UPN-prefix special case
        for one specific well-known synchronization account) -- flagging a synchronization
        service account as inactive is an acceptable, low-cost false positive next to the added
        complexity of detecting it by name pattern.

        Compares against the wall clock at EVALUATION time ([DateTime]::UtcNow), not collection
        time -- the same deliberate, documented time-relative-check pattern AR-002's evaluator
        established first (Test-EntraPostureAccessReviewInstanceHealthControl's own DESCRIPTION):
        re-evaluating the same sealed snapshot later can change this specific result even though
        nothing about the evidence itself changed. ADR-019 ("evaluators never call live APIs") is
        not violated -- reading the local clock is not a network call.

        A User with neither a correlated UserSignInActivity record with a
        lastSuccessfulSignInDateTime NOR its own createdDateTime gives this evaluator no temporal
        signal to judge from at all -- deliberately defaults to Pass rather than Fail in that
        narrow case (its own reason code), the same "absence of evidence is not itself a
        violation" principle COL-003's evaluator already applies. Never produces NotEvaluated or
        Error status -- assigned by the orchestration layer, per USR-005.psd1's
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

    $inactiveThresholdDays = 180

    $users = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'User'

    if (@($users).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'USR-005-NO-USERS'
                Rationale = 'No User entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $signInActivities = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'UserSignInActivity'
    $signInActivityByUserId = @{}
    foreach ($sia in $signInActivities) { $signInActivityByUserId[$sia.entityId] = $sia }

    $now = [DateTime]::UtcNow

    $evaluationResults = @(foreach ($user in $users) {
        $sia = $signInActivityByUserId[$user.entityId]
        $lastSuccessfulSignIn = if ($sia -and -not [string]::IsNullOrWhiteSpace([string]$sia.properties.lastSuccessfulSignInDateTime)) { [DateTime]$sia.properties.lastSuccessfulSignInDateTime } else { $null }
        $createdDateTime = if (-not [string]::IsNullOrWhiteSpace([string]$user.properties.createdDateTime)) { [DateTime]$user.properties.createdDateTime } else { $null }

        $evidenceRef = @([ordered]@{ entityId = $user.entityId; entityType = 'User' })
        if ($sia) { $evidenceRef += [ordered]@{ entityId = $sia.entityId; entityType = 'UserSignInActivity' } }

        if ($lastSuccessfulSignIn) {
            $inactiveDays = [int]($now - $lastSuccessfulSignIn).TotalDays
            if ($inactiveDays -ge $inactiveThresholdDays) {
                [ordered]@{
                    Scope = $user.entityId; Status = 'Fail'; ReasonCode = 'USR-005-INACTIVE-SINCE-LAST-SIGN-IN'
                    Rationale = "User '$($user.displayName)' last successfully signed in $inactiveDays days ago, at or beyond the $inactiveThresholdDays-day inactivity threshold."
                    EvidenceReferences = $evidenceRef
                }
            } else {
                [ordered]@{
                    Scope = $user.entityId; Status = 'Pass'; ReasonCode = 'USR-005-ACTIVE'
                    Rationale = "User '$($user.displayName)' last successfully signed in $inactiveDays days ago, within the $inactiveThresholdDays-day inactivity threshold."
                    EvidenceReferences = $evidenceRef
                }
            }
        } elseif ($createdDateTime) {
            $accountAgeDays = [int]($now - $createdDateTime).TotalDays
            if ($accountAgeDays -gt $inactiveThresholdDays) {
                [ordered]@{
                    Scope = $user.entityId; Status = 'Fail'; ReasonCode = 'USR-005-NEVER-SIGNED-IN'
                    Rationale = "User '$($user.displayName)' has no recorded successful sign-in and was created $accountAgeDays days ago, beyond the $inactiveThresholdDays-day inactivity threshold."
                    EvidenceReferences = $evidenceRef
                }
            } else {
                [ordered]@{
                    Scope = $user.entityId; Status = 'Pass'; ReasonCode = 'USR-005-NEW-ACCOUNT-NOT-YET-SIGNED-IN'
                    Rationale = "User '$($user.displayName)' has no recorded successful sign-in but was created only $accountAgeDays days ago, within the $inactiveThresholdDays-day grace period."
                    EvidenceReferences = $evidenceRef
                }
            }
        } else {
            [ordered]@{
                Scope = $user.entityId; Status = 'Pass'; ReasonCode = 'USR-005-NO-TEMPORAL-SIGNAL'
                Rationale = "User '$($user.displayName)' has neither a recorded sign-in nor a known account creation date -- no evidence to judge inactivity from."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
