#Requires -Version 7.4

function Test-EntraPostureDeviceRegistrationMfaControl {
    <#
        .SYNOPSIS
        CAP-004's evaluator: checks whether any enabled Conditional Access policy requires MFA
        when a user joins or registers a device.

        .DESCRIPTION
        `conditions.applications.includeUserActions` containing the literal value
        `'urn:user:registerdevice'` (confirmed against the live `conditionalAccessApplications`
        reference, re-checked 2026-08-08) combined with `builtInControls` containing `'mfa'` or a
        set `authenticationStrengthId` (which always satisfies MFA -- every built-in strength
        requires at least one MFA-satisfying method). Tenant-wide existence check, same shape as
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
        @($_.properties.conditions.applications.includeUserActions) -contains 'urn:user:registerdevice' -and
        (@($_.properties.grantControls.builtInControls) -contains 'mfa' -or $_.properties.grantControls.authenticationStrengthId)
    })

    if (@($matching).Count -gt 0) {
        $evidenceRef = @($matching | ForEach-Object { [ordered]@{ entityId = $_.entityId; entityType = 'ConditionalAccessPolicy' } })
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'CAP-004-DEVICE-REGISTRATION-MFA-REQUIRED'
                Rationale = "$(@($matching).Count) enabled Conditional Access policy(ies) require MFA for device join/registration."
                EvidenceReferences = $evidenceRef
            }
        )
    } else {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'CAP-004-DEVICE-REGISTRATION-MFA-NOT-REQUIRED'
                Rationale = 'No enabled Conditional Access policy requires MFA for device join/registration.'
                EvidenceReferences = @()
            }
        )
    }

    return ,@($results)
}
