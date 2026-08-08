#Requires -Version 7.4

function Test-EntraPostureBannedPasswordListStrengthControl {
    <#
        .SYNOPSIS
        PAS-002's evaluator: checks whether the tenant's custom banned password list has at
        least 10 entries, once the check itself (PAS-001) is confirmed enabled.

        .DESCRIPTION
        NotApplicable when banned password checking is disabled entirely (or no customized
        "Password Rule Settings" object exists and checking is enabled by its own documented
        default, per PAS-001's own evaluator) but the list itself is empty by that same default
        -- a genuinely fresh tenant with no customized password protection template has an empty
        BannedPasswordList by documented default, which this evaluator correctly reads as
        `bannedPasswordListEntryCount = $null` (no groupSetting object at all) or `0` (an object
        exists but the list is empty), both Fail. 10-entry threshold and "skip when the check
        itself is disabled" gating independently re-derived from EntraFalcon's own publicly
        visible check_Tenant.psm1, then confirmed the underlying field/template against live
        Microsoft Graph documentation (2026-08-08) -- not ported. Never produces NotEvaluated or
        Error status -- assigned by the orchestration layer, per PAS-002.psd1's
        expectedResultSemantics.

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

    $minimumEntryCount = 10

    $groupSettings = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'GroupSetting'
    $passwordSettings = @($groupSettings | Where-Object { $_.displayName -eq 'Password Rule Settings' }) | Select-Object -First 1

    $isBannedPasswordCheckEnabled = (-not $passwordSettings) -or ($null -eq $passwordSettings.properties.enableBannedPasswordCheck) -or ($passwordSettings.properties.enableBannedPasswordCheck -eq $true)

    if (-not $isBannedPasswordCheckEnabled) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'NotApplicable'; ReasonCode = 'PAS-002-BANNED-PASSWORD-CHECK-DISABLED'
                Rationale = 'The custom banned password list check itself is disabled (see PAS-001); list strength is not meaningfully evaluable.'
                EvidenceReferences = @([ordered]@{ entityId = $passwordSettings.entityId; entityType = 'GroupSetting' })
            }
        )
        return ,@($results)
    }

    $entryCount = if ($passwordSettings -and $null -ne $passwordSettings.properties.bannedPasswordListEntryCount) { $passwordSettings.properties.bannedPasswordListEntryCount } else { 0 }

    $results = @(if ($entryCount -lt $minimumEntryCount) {
        [ordered]@{
            Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'PAS-002-BANNED-PASSWORD-LIST-TOO-SHORT'
            Rationale = "The tenant's custom banned password list contains only $entryCount entries (fewer than $minimumEntryCount)."
            EvidenceReferences = if ($passwordSettings) { @([ordered]@{ entityId = $passwordSettings.entityId; entityType = 'GroupSetting' }) } else { @() }
        }
    } else {
        [ordered]@{
            Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'PAS-002-BANNED-PASSWORD-LIST-SUFFICIENT'
            Rationale = "The tenant's custom banned password list contains $entryCount entries (at least $minimumEntryCount)."
            EvidenceReferences = @([ordered]@{ entityId = $passwordSettings.entityId; entityType = 'GroupSetting' })
        }
    })

    return ,@($results)
}
