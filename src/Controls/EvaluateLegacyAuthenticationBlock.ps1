#Requires -Version 7.4

function Test-EntraPostureLegacyAuthenticationBlockControl {
    <#
        .SYNOPSIS
        CAP-003's evaluator: checks whether any enabled Conditional Access policy blocks legacy
        authentication clients.

        .DESCRIPTION
        `conditions.clientAppTypes` containing `'exchangeActiveSync'` or `'other'` -- Microsoft's
        own documented client-app-type values for legacy protocols (confirmed against the live
        `conditionalAccessConditionSet` reference page, re-checked 2026-08-08: "all, browser,
        mobileAppsAndDesktopClients, exchangeActiveSync, easSupported, other") -- combined with a
        `block` grant control is Microsoft's own documented pattern for blocking legacy auth.
        Tenant-wide existence check, same shape as CAP-001.

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
        $types = @($_.properties.conditions.clientAppTypes)
        ($types -contains 'exchangeActiveSync' -or $types -contains 'other') -and
        (@($_.properties.grantControls.builtInControls) -contains 'block')
    })

    if (@($matching).Count -gt 0) {
        $evidenceRef = @($matching | ForEach-Object { [ordered]@{ entityId = $_.entityId; entityType = 'ConditionalAccessPolicy' } })
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'CAP-003-LEGACY-AUTH-BLOCKED'
                Rationale = "$(@($matching).Count) enabled Conditional Access policy(ies) block legacy authentication clients."
                EvidenceReferences = $evidenceRef
            }
        )
    } else {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'CAP-003-LEGACY-AUTH-UNBLOCKED'
                Rationale = 'No enabled Conditional Access policy blocks legacy authentication clients.'
                EvidenceReferences = @()
            }
        )
    }

    return ,@($results)
}
