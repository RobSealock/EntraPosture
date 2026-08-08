#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2, new-evidence phase (batch 7, 2026-08-08): ConvertTo-
    EntraPostureGroupSettingEntity, field shapes confirmed directly against Microsoft Graph's
    "List settings" reference page (re-fetched 2026-08-08) -- see the normalizer's own
    DESCRIPTION.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeGroupSettings.ps1')

    function script:ConvertTo-TestOrderedDictionary {
        param([Parameter(Mandatory)][string]$Json)
        return ConvertFrom-EntraPostureJson -Json $Json
    }
}

Describe 'ConvertTo-EntraPostureGroupSettingEntity' {
    It 'extracts AllowGuestsToBeGroupOwner=true from the Group.Unified values array' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{
  "id": "f0b2d6f5-097d-4177-91af-a24e530b53cc", "displayName": "Group.Unified",
  "templateId": "62375ab9-6b52-47ed-826b-58e47e0e304b",
  "values": [
    { "name": "EnableMIPLabels", "value": "true" },
    { "name": "AllowGuestsToBeGroupOwner", "value": "true" },
    { "name": "AllowGuestsToAccessGroups", "value": "true" }
  ]
}
'@
        $entity = ConvertTo-EntraPostureGroupSettingEntity -RawGroupSetting $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.entityId | Should -Be 'f0b2d6f5-097d-4177-91af-a24e530b53cc'
        $entity.entityType | Should -Be 'GroupSetting'
        $entity.displayName | Should -Be 'Group.Unified'
        $entity.properties.templateId | Should -Be '62375ab9-6b52-47ed-826b-58e47e0e304b'
        $entity.properties.allowGuestsToBeGroupOwner | Should -Be $true
    }

    It 'extracts AllowGuestsToBeGroupOwner=false' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{
  "id": "s1", "displayName": "Group.Unified", "templateId": "62375ab9-6b52-47ed-826b-58e47e0e304b",
  "values": [ { "name": "AllowGuestsToBeGroupOwner", "value": "false" } ]
}
'@
        $entity = ConvertTo-EntraPostureGroupSettingEntity -RawGroupSetting $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.allowGuestsToBeGroupOwner | Should -Be $false
    }

    It 'leaves allowGuestsToBeGroupOwner null when the values array does not contain that name' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{
  "id": "s2", "displayName": "Group.Unified.Guest", "templateId": "08d542b9-071f-4e16-94b0-74abb372e3d9",
  "values": [ { "name": "AllowToAddGuests", "value": "false" } ]
}
'@
        $entity = ConvertTo-EntraPostureGroupSettingEntity -RawGroupSetting $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.allowGuestsToBeGroupOwner | Should -Be $null
    }
}
