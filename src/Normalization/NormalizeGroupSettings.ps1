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

    $allowGuestsToBeGroupOwner = $null
    if ($RawGroupSetting.Contains('values')) {
        foreach ($settingValue in @($RawGroupSetting['values'])) {
            if ($settingValue.Contains('name') -and [string]$settingValue['name'] -eq 'AllowGuestsToBeGroupOwner') {
                $allowGuestsToBeGroupOwner = ([string]$settingValue['value'] -eq 'true')
                break
            }
        }
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
            templateId                = $templateId
            allowGuestsToBeGroupOwner = $allowGuestsToBeGroupOwner
        }
        redacted         = $false
    }
}
