#Requires -Version 7.4

function Test-EntraPostureGuestAccessLevelControl {
    <#
        .SYNOPSIS
        COL-001's evaluator: checks the tenant's AuthorizationPolicy guestUserRoleId setting.

        .DESCRIPTION
        Pass only when set to the "Restricted Guest User" well-known role template ID
        (2af84b1e-32c8-42b7-82bc-daa82404023b) -- the most restrictive of Microsoft's three
        documented options (the other two, "User" and "Guest User", grant broader directory-read
        permissions to every guest). Confirmed directly against the live authorizationPolicy
        Graph reference page, re-fetched 2026-08-08. Same single-entity-scoped shape as
        COL-002/USR-001 (all three read AuthorizationPolicy). Never produces NotEvaluated or
        Error status -- assigned by the orchestration layer, per COL-001.psd1's
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

    $restrictedGuestUserRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b'

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AuthorizationPolicy'

    if (@($policies).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'COL-001-NO-POLICY-FOUND'
                Rationale = 'No AuthorizationPolicy entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($policy in $policies) {
        $isRestricted = [string]$policy.properties.guestUserRoleId -eq $restrictedGuestUserRoleId
        $evidenceRef = @([ordered]@{ entityId = $policy.entityId; entityType = 'AuthorizationPolicy' })

        if ($isRestricted) {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Pass'; ReasonCode = 'COL-001-GUEST-ACCESS-RESTRICTED'
                Rationale = 'guestUserRoleId is set to Restricted Guest User, the most restrictive documented option.'
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Fail'; ReasonCode = 'COL-001-GUEST-ACCESS-NOT-RESTRICTED'
                Rationale = "guestUserRoleId is '$($policy.properties.guestUserRoleId)', not the Restricted Guest User role -- guests have broader directory-read permissions than the most restrictive documented option."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
