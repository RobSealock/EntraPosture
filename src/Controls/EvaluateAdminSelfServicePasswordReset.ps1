#Requires -Version 7.4

function Test-EntraPostureAdminSelfServicePasswordResetControl {
    <#
        .SYNOPSIS
        PAS-005's evaluator: checks the tenant's AuthorizationPolicy.allowedToUseSSPR setting.

        .DESCRIPTION
        Fail when administrators are allowed to use Self-Service Password Reset -- confirmed
        directly against the live authorizationPolicy Graph reference page (re-fetched
        2026-08-08): "Indicates whether administrators of the tenant can use the Self-Service
        Password Reset (SSPR)." Same single-entity-scoped shape as COL-001/002/PAS-001 (all read
        a tenant-wide singleton policy). Never produces NotEvaluated or Error status -- assigned
        by the orchestration layer, per PAS-005.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        One element per AuthorizationPolicy entity (in practice, exactly one).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $policies = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'AuthorizationPolicy'

    if (@($policies).Count -eq 0) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'PAS-005-NO-POLICY-FOUND'
                Rationale = 'No AuthorizationPolicy entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($policy in $policies) {
        $evidenceRef = @([ordered]@{ entityId = $policy.entityId; entityType = 'AuthorizationPolicy' })
        if ($policy.properties.allowedToUseSSPR -eq $true) {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Fail'; ReasonCode = 'PAS-005-ADMIN-SSPR-ALLOWED'
                Rationale = 'Administrators of the tenant are allowed to use Self-Service Password Reset (SSPR).'
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Pass'; ReasonCode = 'PAS-005-ADMIN-SSPR-DISALLOWED'
                Rationale = 'Administrators of the tenant are not allowed to use Self-Service Password Reset (SSPR).'
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
