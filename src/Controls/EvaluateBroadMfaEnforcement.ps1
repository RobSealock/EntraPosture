#Requires -Version 7.4

function Test-EntraPostureBroadMfaEnforcementControl {
    <#
        .SYNOPSIS
        CAP-009's evaluator: checks whether any enabled Conditional Access policy requires MFA
        for all users tenant-wide.

        .DESCRIPTION
        Distinct from PRIV-001/CA-001 (which check Tier-0 administrator coverage specifically):
        this control checks the broader population, `conditions.users.includeUsers` containing
        the literal `'All'` combined with an MFA-satisfying grant (`builtInControls` containing
        `'mfa'`, or a set `authenticationStrengthId`). Tenant-wide existence check, same shape as
        CAP-001.

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
        @($_.properties.conditions.users.includeUsers) -contains 'All' -and
        (@($_.properties.grantControls.builtInControls) -contains 'mfa' -or $_.properties.grantControls.authenticationStrengthId)
    })

    if (@($matching).Count -gt 0) {
        $evidenceRef = @($matching | ForEach-Object { [ordered]@{ entityId = $_.entityId; entityType = 'ConditionalAccessPolicy' } })
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'CAP-009-MFA-ENFORCED'
                Rationale = "$(@($matching).Count) enabled Conditional Access policy(ies) require MFA for all users."
                EvidenceReferences = $evidenceRef
            }
        )
    } else {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'CAP-009-MFA-NOT-ENFORCED'
                Rationale = 'No enabled Conditional Access policy requires MFA for all users tenant-wide.'
                EvidenceReferences = @()
            }
        )
    }

    return ,@($results)
}
