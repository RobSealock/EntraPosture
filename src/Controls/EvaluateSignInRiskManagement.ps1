#Requires -Version 7.4

function Test-EntraPostureSignInRiskManagementControl {
    <#
        .SYNOPSIS
        CAP-007's evaluator: checks whether any enabled Conditional Access policy acts on
        sign-in risk level.

        .DESCRIPTION
        `conditions.signInRiskLevels` non-empty combined with a non-trivial grant (`block`, any
        `builtInControls`, or a set `authenticationStrengthId`) -- a policy scoped to a risk
        level with no grant governs nothing. Tenant-wide existence check, same shape as CAP-001.

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
        (@($_.properties.grantControls.builtInControls).Count -gt 0 -or $_.properties.grantControls.authenticationStrengthId)
    })

    if (@($matching).Count -gt 0) {
        $evidenceRef = @($matching | ForEach-Object { [ordered]@{ entityId = $_.entityId; entityType = 'ConditionalAccessPolicy' } })
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'CAP-007-SIGN-IN-RISK-MANAGED'
                Rationale = "$(@($matching).Count) enabled Conditional Access policy(ies) act on sign-in risk level."
                EvidenceReferences = $evidenceRef
            }
        )
    } else {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'CAP-007-SIGN-IN-RISK-NOT-MANAGED'
                Rationale = 'No enabled Conditional Access policy acts on sign-in risk level.'
                EvidenceReferences = @()
            }
        )
    }

    return ,@($results)
}
