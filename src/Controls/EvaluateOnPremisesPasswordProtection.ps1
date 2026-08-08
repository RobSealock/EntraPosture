#Requires -Version 7.4

function Test-EntraPostureOnPremisesPasswordProtectionControl {
    <#
        .SYNOPSIS
        PAS-003's evaluator: checks whether Entra password protection is enforced (not just
        audited) for the on-premises environment, once the check itself (PAS-001) is confirmed
        enabled.

        .DESCRIPTION
        NotApplicable when banned password checking is disabled entirely (same gate PAS-002's
        evaluator applies). Otherwise Pass only if EnableBannedPasswordCheckOnPremises is true
        AND BannedPasswordCheckOnPremisesMode is 'Enforce' (case-insensitive) -- the documented
        default for the mode field is 'Audit', not 'Enforce' (confirmed live 2026-08-08 against a
        worked example of this exact "Password Rule Settings" groupSettingTemplate), so a tenant
        that has never customized this template Fails, not Passes: audit mode logs violations
        without blocking them. Never produces NotEvaluated or Error status -- assigned by the
        orchestration layer, per PAS-003.psd1's expectedResultSemantics.

        .PARAMETER EvidenceProvider
        A handle from New-EntraPostureEvidenceProvider.

        .OUTPUTS
        Array of ordered dictionaries: Scope, Status, ReasonCode, Rationale, EvidenceReferences.
        Always exactly one element (tenant-scoped).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary[]])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$EvidenceProvider
    )

    $groupSettings = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'GroupSetting'
    $passwordSettings = @($groupSettings | Where-Object { $_.displayName -eq 'Password Rule Settings' }) | Select-Object -First 1

    $isBannedPasswordCheckEnabled = (-not $passwordSettings) -or ($null -eq $passwordSettings.properties.enableBannedPasswordCheck) -or ($passwordSettings.properties.enableBannedPasswordCheck -eq $true)

    if (-not $isBannedPasswordCheckEnabled) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'PAS-003-BANNED-PASSWORD-CHECK-DISABLED'
                Rationale = 'The custom banned password list check itself is disabled (see PAS-001); on-premises enforcement is not meaningfully evaluable.'
                EvidenceReferences = @([ordered]@{ entityId = $passwordSettings.entityId; entityType = 'GroupSetting' })
            }
        )
        return ,@($results)
    }

    $onPremEnabled = $passwordSettings -and $passwordSettings.properties.enableBannedPasswordCheckOnPremises -eq $true
    $onPremMode = if ($passwordSettings -and -not [string]::IsNullOrWhiteSpace([string]$passwordSettings.properties.bannedPasswordCheckOnPremisesMode)) { [string]$passwordSettings.properties.bannedPasswordCheckOnPremisesMode } else { 'Audit' }
    $isEnforced = $onPremMode.Trim().ToLowerInvariant() -eq 'enforce'

    $results = @(if ($onPremEnabled -and $isEnforced) {
        [ordered]@{
            Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'PAS-003-ON-PREMISES-ENFORCED'
            Rationale = 'On-premises password protection is enabled and its mode is Enforce.'
            EvidenceReferences = @([ordered]@{ entityId = $passwordSettings.entityId; entityType = 'GroupSetting' })
        }
    } else {
        [ordered]@{
            Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'PAS-003-ON-PREMISES-NOT-ENFORCED'
            Rationale = "On-premises password protection is not fully enforced (EnableBannedPasswordCheckOnPremises=$onPremEnabled, BannedPasswordCheckOnPremisesMode='$onPremMode')."
            EvidenceReferences = if ($passwordSettings) { @([ordered]@{ entityId = $passwordSettings.entityId; entityType = 'GroupSetting' }) } else { @() }
        }
    })

    return ,@($results)
}
