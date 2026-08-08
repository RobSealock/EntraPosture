#Requires -Version 7.4

function ConvertTo-EntraPostureGroupSettingEntity {
    <#
        .SYNOPSIS
        Normalizes one raw Graph groupSetting object (from GET /v1.0/groupSettings) into a
        canonical Entity record.

        .DESCRIPTION
        Field allowlist per section 8.4: id, displayName, templateId, and one specific
        flattened boolean extracted out of the generic name-value `values` collection --
        allowGuestsToBeGroupOwner, COL-003's own field. groupSetting's `values` property is a
        generic settingValue collection (`{ name, value }` string pairs keyed by the owning
        groupSettingTemplate, e.g. "Group.Unified"), confirmed directly against the live
        "List settings" Graph reference page's own example response (re-fetched 2026-08-08) --
        a wholly different shape from every other entity this project normalizes (which all have
        named top-level fields), so this collector/normalizer pair is new infrastructure, not a
        field extension to an already-called endpoint (unlike COL-001/002's guestUserRoleId/
        allowInvitesFrom, both direct AuthorizationPolicy fields).

        A tenant that has never customized its Group.Unified settings has no groupSetting object
        in the /groupSettings collection at all -- "by default, all groups inherit the preset
        defaults," per the same reference page -- so a groupSetting entity's absence is not
        itself ambiguous: COL-003's evaluator treats it as the template's own documented default
        (allowGuestsToBeGroupOwner = false), not as missing evidence. This normalizer only
        extracts the value when it is actually present in a given groupSetting's `values` array,
        leaving the property null otherwise -- the evaluator's own responsibility to interpret
        "no matching groupSetting at all" as the documented default, not this normalizer's.

        PAS-001/002/003/004 fields (added 2026-08-08, VNext build order item 2, the 109-row
        backlog completion pass): the "Password Rule Settings" groupSettingTemplate
        (templateId `5cf42378-d67d-4f36-ba46-e8b86229381d`, confirmed directly against a live
        worked example of this exact template re-fetched 2026-08-08) carries
        enableBannedPasswordCheck, enableBannedPasswordCheckOnPremises,
        bannedPasswordCheckOnPremisesMode, lockoutDurationInSeconds, and lockoutThreshold as
        further named values in the same generic `values` array Group.Unified uses --
        extracted the same way, by name, regardless of which template a given groupSetting
        record actually is (a record from a different template simply has none of these names
        present, leaving every field null, the same "extract what's present" discipline every
        other normalizer in this project already follows). bannedPasswordListEntryCount is an
        aggregated count of the tab/comma/semicolon/newline-delimited `BannedPasswordList` raw
        value, never the raw list itself -- this project's own redaction discipline (the same
        "counts, not raw contents" pattern `AccessReviewInstance`'s decision aggregation and
        `ServicePrincipal`'s credential counts already established) applies here because the raw
        list is itself sensitive password material, not because of any general size concern.

        .PARAMETER RawGroupSetting
        One element of GET /v1.0/groupSettings' 'value' array.

        .PARAMETER TenantScope
        .PARAMETER CollectorVersion
        .PARAMETER SourceEndpoint
        .PARAMETER CollectedAt

        .OUTPUTS
        Ordered dictionary matching entity.schema.json.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$RawGroupSetting,

        [Parameter(Mandatory)]
        [string]$TenantScope,

        [Parameter(Mandatory)]
        [string]$CollectorVersion,

        [Parameter(Mandatory)]
        [string]$SourceEndpoint,

        [Parameter(Mandatory)]
        [string]$CollectedAt
    )

    $entityId = [string]$RawGroupSetting['id']
    $displayName = if ($RawGroupSetting.Contains('displayName')) { $RawGroupSetting['displayName'] } else { $null }
    $templateId = if ($RawGroupSetting.Contains('templateId')) { $RawGroupSetting['templateId'] } else { $null }

    $rawValues = if ($RawGroupSetting.Contains('values')) { @($RawGroupSetting['values']) } else { @() }

    $getStringValue = {
        param([string]$Name)
        foreach ($settingValue in $rawValues) {
            if ($settingValue.Contains('name') -and [string]$settingValue['name'] -eq $Name) {
                return [string]$settingValue['value']
            }
        }
        return $null
    }
    $getBoolValue = {
        param([string]$Name)
        $raw = & $getStringValue -Name $Name
        if ($null -eq $raw) { return $null }
        return ($raw -eq 'true')
    }
    $getIntValue = {
        param([string]$Name)
        $raw = & $getStringValue -Name $Name
        if ($null -eq $raw) { return $null }
        $parsed = 0
        if ([int]::TryParse($raw, [ref]$parsed)) { return $parsed }
        return $null
    }

    $bannedPasswordListEntryCount = $null
    $rawBannedPasswordList = & $getStringValue -Name 'BannedPasswordList'
    if ($null -ne $rawBannedPasswordList) {
        $entries = @($rawBannedPasswordList -split '[\t,;\r\n]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $bannedPasswordListEntryCount = @($entries | Select-Object -Unique).Count
    }

    return [ordered]@{
        entityId         = $entityId
        entityType       = 'GroupSetting'
        tenantScope      = $TenantScope
        displayName      = $displayName
        collectedAt      = $CollectedAt
        collectorVersion = $CollectorVersion
        sourceEndpoint   = $SourceEndpoint
        properties       = [ordered]@{
            templateId                          = $templateId
            allowGuestsToBeGroupOwner            = & $getBoolValue -Name 'AllowGuestsToBeGroupOwner'
            enableGroupCreation                  = & $getBoolValue -Name 'EnableGroupCreation'
            enableBannedPasswordCheck            = & $getBoolValue -Name 'EnableBannedPasswordCheck'
            bannedPasswordListEntryCount         = $bannedPasswordListEntryCount
            enableBannedPasswordCheckOnPremises  = & $getBoolValue -Name 'EnableBannedPasswordCheckOnPremises'
            bannedPasswordCheckOnPremisesMode    = & $getStringValue -Name 'BannedPasswordCheckOnPremisesMode'
            lockoutDurationInSeconds             = & $getIntValue -Name 'LockoutDurationInSeconds'
            lockoutThreshold                     = & $getIntValue -Name 'LockoutThreshold'
        }
        redacted         = $false
    }
}
