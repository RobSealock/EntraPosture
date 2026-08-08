#Requires -Version 7.4

function Test-EntraPostureAccountLockoutSettingsControl {
    <#
        .SYNOPSIS
        PAS-004's evaluator: checks whether the tenant's account lockout settings
        (LockoutThreshold, LockoutDurationInSeconds) are at least as strict as Microsoft's own
        documented secure defaults.

        .DESCRIPTION
        Microsoft's own documented defaults for this "Password Rule Settings" groupSettingTemplate
        are LockoutThreshold=10, LockoutDurationInSeconds=60 (confirmed live 2026-08-08 against a
        worked example of this exact template) -- Pass when no customized settings object exists
        at all (the tenant is running those defaults), or when both configured values are at
        least as strict as the defaults (threshold no higher, duration no lower). Deliberately
        simpler than EntraFalcon's own PAS-004 check, which additionally estimates an
        attempts-per-hour guessing rate assuming the lockout duration increases by a fixed amount
        per cycle -- that source's own comment states "Microsoft does not publish the exact
        increase curve, so this is an approximation," an assumption this project cannot
        independently verify and therefore does not replicate; a direct threshold/duration
        comparison against Microsoft's own documented defaults is the citable subset of that
        check. Never produces NotEvaluated or Error status -- assigned by the orchestration
        layer, per PAS-004.psd1's expectedResultSemantics.

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

    $defaultLockoutThreshold = 10
    $defaultLockoutDurationInSeconds = 60

    $groupSettings = Get-EntraPostureEntity -Provider $EvidenceProvider -EntityType 'GroupSetting'
    $passwordSettings = @($groupSettings | Where-Object { $_.displayName -eq 'Password Rule Settings' }) | Select-Object -First 1

    if (-not $passwordSettings) {
        $results = @(
            [ordered]@{
                Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'PAS-004-DEFAULT-LOCKOUT-SETTINGS'
                Rationale = 'No customized Password Rule Settings object exists; Microsoft''s documented secure defaults (LockoutThreshold=10, LockoutDurationInSeconds=60) apply.'
                EvidenceReferences = @()
            }
        )
        return ,@($results)
    }

    $threshold = $passwordSettings.properties.lockoutThreshold
    $duration = $passwordSettings.properties.lockoutDurationInSeconds
    $evidenceRef = @([ordered]@{ entityId = $passwordSettings.entityId; entityType = 'GroupSetting' })

    $isAtLeastAsStrict = ($null -ne $threshold) -and ($null -ne $duration) -and ($threshold -le $defaultLockoutThreshold) -and ($duration -ge $defaultLockoutDurationInSeconds)

    $results = @(if ($isAtLeastAsStrict) {
        [ordered]@{
            Scope = 'tenant'; Status = 'Pass'; ReasonCode = 'PAS-004-LOCKOUT-SETTINGS-STRICT-ENOUGH'
            Rationale = "Configured lockout settings (threshold=$threshold, duration=${duration}s) are at least as strict as Microsoft's documented defaults (threshold=$defaultLockoutThreshold, duration=${defaultLockoutDurationInSeconds}s)."
            EvidenceReferences = $evidenceRef
        }
    } else {
        [ordered]@{
            Scope = 'tenant'; Status = 'Fail'; ReasonCode = 'PAS-004-LOCKOUT-SETTINGS-WEAK'
            Rationale = "Configured lockout settings (threshold=$threshold, duration=${duration}s) are weaker than Microsoft's documented defaults (threshold=$defaultLockoutThreshold, duration=${defaultLockoutDurationInSeconds}s), or could not be parsed."
            EvidenceReferences = $evidenceRef
        }
    })

    return ,@($results)
}
