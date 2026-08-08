#Requires -Version 7.4

function Test-EntraPostureSecurityInfoRegistrationRestrictionControl {
    <#
        .SYNOPSIS
        CAP-002's evaluator: checks whether any enabled Conditional Access policy governs the
        "register security info" user action.

        .DESCRIPTION
        `conditions.applications.includeUserActions` containing the literal value
        `'urn:user:registersecurityinfo'` is confirmed directly (Microsoft Graph
        `conditionalAccessApplications` reference, re-checked 2026-08-08). A qualifying policy
        must carry at least one non-trivial grant (`block`, or any control in `builtInControls`,
        or an `authenticationStrengthId`) -- a policy that targets the action with an empty grant
        set governs nothing. Tenant-wide existence check, same shape as CAP-001.

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
        @($_.properties.conditions.applications.includeUserActions) -contains 'urn:user:registersecurityinfo' -and
        (@($_.properties.grantControls.builtInControls) -contains 'block' -or
         @($_.properties.grantControls.builtInControls).Count -gt 0 -or
         $_.properties.grantControls.authenticationStrengthId)
    })

    if (@($matching).Count -gt 0) {
        $evidenceRef = @($matching | ForEach-Object { [ordered]@{ entityId = $_.entityId; entityType = 'ConditionalAccessPolicy' } })
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'CAP-002-SECURITY-INFO-REGISTRATION-RESTRICTED'
                Rationale = "$(@($matching).Count) enabled Conditional Access policy(ies) govern security info registration."
                EvidenceReferences = $evidenceRef
            }
        )
    } else {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'CAP-002-SECURITY-INFO-REGISTRATION-UNRESTRICTED'
                Rationale = 'No enabled Conditional Access policy governs the "register security info" user action.'
                EvidenceReferences = @()
            }
        )
    }

    return ,@($results)
}
