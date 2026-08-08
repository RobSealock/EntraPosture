#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 9 (AR-002) extended ConvertTo-EntraPostureAccessReviewDefinitionEntity
    to also capture settings.autoApplyDecisionsEnabled, needed by AR-002's
    AR-002-DECISIONS-NOT-APPLIED check. No dedicated normalizer test file existed for this
    function before (only indirect coverage via AR-001's fixture-built test entities and the
    vertical-slice pipeline) -- added here alongside the extension.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeAccessReviewDefinition.ps1')

    function script:ConvertTo-TestOrderedDictionary {
        param([Parameter(Mandatory)][string]$Json)
        return ConvertFrom-EntraPostureJson -Json $Json
    }
}

Describe 'ConvertTo-EntraPostureAccessReviewDefinitionEntity: autoApplyDecisionsEnabled (AR-002)' {
    It 'maps settings.autoApplyDecisionsEnabled when present and true' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{ "id": "def-1", "displayName": "Group review", "status": "Active",
  "scope": { "query": "/groups/g1/transitiveMembers" },
  "settings": { "autoApplyDecisionsEnabled": true } }
'@
        $entity = ConvertTo-EntraPostureAccessReviewDefinitionEntity -RawDefinition $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.autoApplyDecisionsEnabled | Should -BeTrue
    }

    It 'maps settings.autoApplyDecisionsEnabled when present and false' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{ "id": "def-2", "settings": { "autoApplyDecisionsEnabled": false } }
'@
        $entity = ConvertTo-EntraPostureAccessReviewDefinitionEntity -RawDefinition $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.autoApplyDecisionsEnabled | Should -BeFalse
    }

    It 'leaves autoApplyDecisionsEnabled explicitly null (not assumed false) when settings is entirely absent' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "id": "def-3" }'
        $entity = ConvertTo-EntraPostureAccessReviewDefinitionEntity -RawDefinition $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.Contains('autoApplyDecisionsEnabled') | Should -BeTrue
        $entity.properties.autoApplyDecisionsEnabled | Should -BeNullOrEmpty
    }
}
