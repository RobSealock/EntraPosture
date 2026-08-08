#Requires -Version 7.4

function Test-EntraPostureDeviceCodeFlowRestrictionControl {
    <#
        .SYNOPSIS
        CAP-001's evaluator: checks whether any enabled Conditional Access policy blocks sign-ins
        using the device code authentication flow.

        .DESCRIPTION
        Tenant-wide existence check, the same single-result-per-tenant shape USR-001/AC-001 use.
        `conditions.authenticationFlowTransferMethods` holding the literal value `'deviceCodeFlow'`
        is confirmed directly against the live `conditionalAccessAuthenticationFlows` Graph
        reference page (re-fetched 2026-08-08): "The possible values are: none, deviceCodeFlow,
        authenticationTransfer, unknownFutureValue." A qualifying policy must also carry a
        `block` grant control -- a policy merely scoped to this condition without a block grant
        (e.g. one that requires MFA instead) does not restrict the flow, it only adds a
        requirement to it, so is not counted as a match. Never produces NotEvaluated or Error
        status -- assigned by the orchestration layer, per CAP-001.psd1's
        expectedResultSemantics.

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
        $_.properties.conditions.authenticationFlowTransferMethods -eq 'deviceCodeFlow' -and
        @($_.properties.grantControls.builtInControls) -contains 'block'
    })

    if (@($matching).Count -gt 0) {
        $evidenceRef = @($matching | ForEach-Object { [ordered]@{ entityId = $_.entityId; entityType = 'ConditionalAccessPolicy' } })
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'Pass'
                ReasonCode         = 'CAP-001-DEVICE-CODE-FLOW-BLOCKED'
                Rationale          = "$(@($matching).Count) enabled Conditional Access policy(ies) block sign-ins using the device code authentication flow."
                EvidenceReferences = $evidenceRef
            }
        )
    } else {
        $results = @(
            [ordered]@{
                Scope              = 'tenant'
                Status             = 'Fail'
                ReasonCode         = 'CAP-001-DEVICE-CODE-FLOW-UNRESTRICTED'
                Rationale          = 'No enabled Conditional Access policy blocks sign-ins using the device code authentication flow.'
                EvidenceReferences = @()
            }
        )
    }

    return ,@($results)
}
