#Requires -Version 7.4

function Test-EntraPostureBannedPasswordCheckControl {
    <#
        .SYNOPSIS
        PAS-001's evaluator: checks the tenant's "Password Rule Settings" group settings for
        EnableBannedPasswordCheck.

        .DESCRIPTION
        Same "GroupSetting entity may not exist at all, apply the template's own documented
        default" pattern COL-003's evaluator already established, but with the opposite default
        direction: EnableBannedPasswordCheck's own documented default is true (confirmed live
        2026-08-08, re-fetching a live worked example of this exact "Password Rule Settings"
        groupSettingTemplate, templateId 5cf42378-d67d-4f36-ba46-e8b86229381d), so a tenant that
        has never customized this template is Pass, not Fail. Single tenant-scoped result, same
        shape as COL-002/003. Never produces NotEvaluated or Error status -- assigned by the
        orchestration layer, per PAS-001.psd1's expectedResultSemantics.

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

    $results = @(if (-not $passwordSettings -or $null -eq $passwordSettings.properties.enableBannedPasswordCheck -or $passwordSettings.properties.enableBannedPasswordCheck -eq $true) {
        [ordered]@{
            Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'PAS-001-BANNED-PASSWORD-CHECK-ENABLED'
            Rationale = 'The tenant''s custom banned password list check is enabled (or no customized Password Rule Settings object exists, and Microsoft''s own documented default for EnableBannedPasswordCheck is true).'
            EvidenceReferences = if ($passwordSettings) { @([ordered]@{ entityId = $passwordSettings.entityId; entityType = 'GroupSetting' }) } else { @() }
        }
    } else {
        [ordered]@{
            Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'PAS-001-BANNED-PASSWORD-CHECK-DISABLED'
            Rationale = 'The tenant''s custom banned password list check (EnableBannedPasswordCheck) is explicitly disabled.'
            EvidenceReferences = @([ordered]@{ entityId = $passwordSettings.entityId; entityType = 'GroupSetting' })
        }
    })

    return ,@($results)
}
