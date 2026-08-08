#Requires -Version 7.4

function Test-EntraPostureCombinedRiskPolicyControl {
    <#
        .SYNOPSIS
        CAP-006's evaluator: checks whether any single enabled Conditional Access policy acts on
        BOTH sign-in risk and user risk together.

        .DESCRIPTION
        Distinct from CAP-007/CAP-008 (which each check that risk type is managed by ANY
        policy, not necessarily the same one): this control specifically looks for one policy
        combining both `conditions.signInRiskLevels` and `conditions.userRiskLevels` non-empty,
        with a non-trivial grant -- the "combined risk policy" pattern named in the source
        finding this control's title comes from. A tenant may pass CAP-007 and CAP-008
        independently via two separate policies while still failing this one; that is the
        intended, distinct signal, not overlap.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        Single tenant-scoped result.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ConditionalAccessPolicy'
    $enabledPolicies = @($policies | Where-Object { $_.properties.state -eq 'enabled' })

    $matching = @($enabledPolicies | Where-Object {
        @($_.properties.conditions.signInRiskLevels).Count -gt 0 -and
        @($_.properties.conditions.userRiskLevels).Count -gt 0 -and
        (@($_.properties.grantControls.builtInControls).Count -gt 0 -or $_.properties.grantControls.authenticationStrengthId)
    })

    if (@($matching).Count -gt 0) {
        $evidenceRef = @($matching | ForEach-Object { [ordered]@{ entityId = $_.entityId; entityType = 'ConditionalAccessPolicy' } })
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'CAP-006-COMBINED-RISK-POLICY-CONFIGURED'
                Rationale = "$(@($matching).Count) enabled Conditional Access policy(ies) act on both sign-in risk and user risk together."
                EvidenceReferences = $evidenceRef
            }
        )
    } else {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'CAP-006-COMBINED-RISK-POLICY-NOT-CONFIGURED'
                Rationale = 'No single enabled Conditional Access policy acts on both sign-in risk and user risk together.'
                EvidenceReferences = @()
            }
        )
    }

    return ,@($results)
}
