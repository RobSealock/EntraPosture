#Requires -Version 7.4

function Test-EntraPosturePhishingResistantMfaEnforcementControl {
    <#
        .SYNOPSIS
        CAP-005's evaluator: checks whether any enabled Conditional Access policy requires a
        phishing-resistant authentication strength.

        .DESCRIPTION
        A policy's `grantControls.authenticationStrengthId` is resolved against collected
        AuthenticationStrengthPolicy evidence; a match is phishing-resistant when its
        `allowedCombinations` is a non-empty subset of the three methods Microsoft's own
        built-in "Phishing-resistant MFA strength" allows -- `windowsHelloForBusiness`, `fido2`,
        `x509CertificateMultiFactor` (confirmed directly against the live "Overview of
        Conditional Access Authentication Strengths" page and the `authenticationMethodModes`
        enum, re-checked 2026-08-08). Matching by allowed-combination subset, not by
        `policyType`/`displayName`, so a custom authentication strength that happens to allow
        only these methods is counted too, not just the unmodifiable built-in one. Tenant-wide
        existence check, same shape as CAP-001.

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

    $phishingResistantMethods = @('windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor')

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'ConditionalAccessPolicy'
    $enabledPolicies = @($policies | Where-Object { $_.properties.state -eq 'enabled' })
    $strengths = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AuthenticationStrengthPolicy'

    $phishingResistantStrengthIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($strength in $strengths) {
        $combinations = @($strength.properties.allowedCombinations)
        if (@($combinations).Count -gt 0 -and @($combinations | Where-Object { $phishingResistantMethods -notcontains $_ }).Count -eq 0) {
            [void]$phishingResistantStrengthIds.Add($strength.entityId)
        }
    }

    $matching = @($enabledPolicies | Where-Object {
        $sid = $_.properties.grantControls.authenticationStrengthId
        -not [string]::IsNullOrWhiteSpace($sid) -and $phishingResistantStrengthIds.Contains($sid)
    })

    if (@($matching).Count -gt 0) {
        $evidenceRef = @($matching | ForEach-Object { [ordered]@{ entityId = $_.entityId; entityType = 'ConditionalAccessPolicy' } })
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'CAP-005-PHISHING-RESISTANT-MFA-ENFORCED'
                Rationale = "$(@($matching).Count) enabled Conditional Access policy(ies) require a phishing-resistant authentication strength."
                EvidenceReferences = $evidenceRef
            }
        )
    } else {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'CAP-005-PHISHING-RESISTANT-MFA-NOT-ENFORCED'
                Rationale = 'No enabled Conditional Access policy requires a phishing-resistant authentication strength.'
                EvidenceReferences = @()
            }
        )
    }

    return ,@($results)
}
