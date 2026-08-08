#Requires -Version 7.4

function Test-EntraPostureBitlockerKeyReadAccessControl {
    <#
        .SYNOPSIS
        USR-003's evaluator: checks the tenant's AuthorizationPolicy.defaultUserRolePermissions.
        allowedToReadBitlockerKeysForOwnedDevice setting.

        .DESCRIPTION
        Fail when users are allowed to read the BitLocker recovery key of devices they own --
        confirmed directly against the live defaultUserRolePermissions Graph reference page
        (re-fetched 2026-08-08): "Indicates whether the registered owners of a device can read
        their own BitLocker recovery keys with default user role." Evaluated directly from this
        tenant-wide policy setting regardless of whether any device currently exists in the
        tenant -- the setting is a standing capability, not conditioned on current device count,
        so this evaluator (unlike EntraFalcon's own equivalent check) needs no Device evidence
        domain at all. Never produces NotEvaluated or Error status -- assigned by the
        orchestration layer, per USR-003.psd1's expectedResultSemantics.

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
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'USR-003-NO-POLICY-FOUND'
                Rationale = 'No AuthorizationPolicy entity was present in the evidence set.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $evaluationResults = @(foreach ($policy in $policies) {
        $evidenceRef = @([ordered]@{ entityId = $policy.entityId; entityType = 'AuthorizationPolicy' })
        if ($policy.properties.allowedToReadBitlockerKeysForOwnedDevice -eq $true) {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Fail'; ReasonCode = 'USR-003-BITLOCKER-KEY-READ-ALLOWED'
                Rationale = 'Users are allowed to read the BitLocker recovery key of devices they own.'
                EvidenceReferences = $evidenceRef
            }
        } else {
            [ordered]@{
                Scope = $policy.entityId; Status = 'Pass'; ReasonCode = 'USR-003-BITLOCKER-KEY-READ-RESTRICTED'
                Rationale = 'Users are not allowed to read the BitLocker recovery key of devices they own.'
                EvidenceReferences = $evidenceRef
            }
        }
    })

    return ,@($evaluationResults)
}
