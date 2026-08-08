#Requires -Version 7.4

function Test-EntraPostureGuestInviteRestrictionControl {
    <#
        .SYNOPSIS
        COL-002's evaluator: checks the tenant's AuthorizationPolicy allowInvitesFrom setting.

        .DESCRIPTION
        Fail when allowInvitesFrom is 'everyone' or 'adminsGuestInvitersAndAllMembers' -- both
        let ordinary (non-admin) members invite guests -- Pass when it is
        'adminsAndGuestInviters' (admin roles only) or 'none' (nobody). Confirmed directly
        against the live authorizationPolicy Graph reference page, re-fetched 2026-08-08:
        "everyone... The default setting for all cloud environments except US Government," the
        broadest of the four documented values. Same single-entity-scoped shape as
        USR-001/COL-001 (both also read AuthorizationPolicy). Never produces NotEvaluated or
        Error status -- assigned by the orchestration layer, per COL-002.psd1's
        expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per AuthorizationPolicy entity (in practice, exactly one).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AuthorizationPolicy'

    if (@($policies).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'COL-002-NO-POLICY-FOUND'
                Rationale = 'No AuthorizationPolicy entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $weakValues = @('everyone', 'adminsGuestInvitersAndAllMembers')

    $evaluationResults = @(foreach ($policy in $policies) {
        $isWeak = $weakValues -contains $policy.properties.allowInvitesFrom
        $evidenceRef = @([ordered]@{ entityId = $policy.entityId; entityType = 'AuthorizationPolicy' })

        if ($isWeak) {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Fail'; ReasonCode = 'COL-002-GUEST-INVITE-UNRESTRICTED'
                Rationale = "allowInvitesFrom is '$($policy.properties.allowInvitesFrom)' -- non-admin members can invite guests."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Pass'; ReasonCode = 'COL-002-GUEST-INVITE-RESTRICTED'
                Rationale = "allowInvitesFrom is '$($policy.properties.allowInvitesFrom)' -- guest invitations are restricted to admin roles or disabled entirely."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
