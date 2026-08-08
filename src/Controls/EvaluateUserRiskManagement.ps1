#Requires -Version 7.4

function Test-EntraPostureUserRiskManagementControl {
    <#
        .SYNOPSIS
        CAP-008's evaluator: checks whether any enabled Conditional Access policy acts on user
        risk level.

        .DESCRIPTION
        Same shape as CAP-007 (Test-EntraPostureSignInRiskManagementControl), reading
        `conditions.userRiskLevels` instead of `signInRiskLevels` -- a distinct Entra ID
        Protection risk signal, not a duplicate check.

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
        @($_.properties.conditions.userRiskLevels).Count -gt 0 -and
        (@($_.properties.grantControls.builtInControls).Count -gt 0 -or $_.properties.grantControls.authenticationStrengthId)
    })

    if (@($matching).Count -gt 0) {
        $evidenceRef = @($matching | ForEach-Object { [ordered]@{ entityId = $_.entityId; entityType = 'ConditionalAccessPolicy' } })
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'CAP-008-USER-RISK-MANAGED'
                Rationale = "$(@($matching).Count) enabled Conditional Access policy(ies) act on user risk level."
                EvidenceReferences = $evidenceRef
            }
        )
    } else {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'CAP-008-USER-RISK-NOT-MANAGED'
                Rationale = 'No enabled Conditional Access policy acts on user risk level.'
                EvidenceReferences = @()
            }
        )
    }

    return ,@($results)
}
