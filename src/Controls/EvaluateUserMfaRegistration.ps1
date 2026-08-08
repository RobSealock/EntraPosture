#Requires -Version 7.4

function Test-EntraPostureUserMfaRegistrationControl {
    <#
        .SYNOPSIS
        USR-012's evaluator: for each collected UserRegistrationDetails record, checks
        isMfaRegistered.

        .DESCRIPTION
        Fail when a user has not registered a strong authentication method for multifactor
        authentication -- confirmed directly against the live userRegistrationDetails resource
        reference page (re-fetched 2026-08-08): "Indicates whether the user has registered a
        strong authentication method for multifactor authentication." isMfaRegistered, not
        isMfaCapable, is deliberately the field checked here -- isMfaCapable additionally
        requires the method to be currently allowed by the tenant's authentication methods
        policy, which conflates "has a real MFA factor" with "policy currently permits using it";
        this control is about factor registration specifically, matching its own title. The
        underlying report already excludes disabled and soft-deleted users (confirmed on the same
        "Authentication Methods Activity" guidance page), so no additional accountEnabled
        filtering is needed here. Never produces NotEvaluated or Error status -- assigned by the
        orchestration layer, per USR-012.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $registrationDetails = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'UserRegistrationDetails'

    if (@($registrationDetails).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'USR-012-NO-REGISTRATION-DETAILS'
                Rationale = 'No UserRegistrationDetails entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($detail in $registrationDetails) {
        $evidenceRef = @([ordered]@{ entityId = $detail.entityId; entityType = 'UserRegistrationDetails' })

        if ($detail.properties.isMfaRegistered -eq $true) {
            [ordered]@{
                Scope = $detail.entityId; Status = 'Pass'; ReasonCode = 'USR-012-MFA-REGISTERED'
                Rationale = "User '$($detail.displayName)' has registered a strong authentication method for multifactor authentication."
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $detail.entityId; Status = 'Fail'; ReasonCode = 'USR-012-NO-MFA-REGISTERED'
                Rationale = "User '$($detail.displayName)' has not registered any strong authentication method for multifactor authentication."
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
