#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2, new-evidence phase (batch 8, 2026-08-08): ConvertTo-
    EntraPostureUserSignInActivityEntity, field shapes confirmed directly against Microsoft
    Graph's signInActivity resource reference page (re-fetched 2026-08-08) -- see the
    normalizer's own DESCRIPTION.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeUserSignInActivity.ps1')

    function script:ConvertTo-TestOrderedDictionary {
        param([Parameter(Mandatory)][string]$Json)
        return ConvertFrom-EntraPostureJson -Json $Json
    }
}

Describe 'ConvertTo-EntraPostureUserSignInActivityEntity' {
    It 'extracts all three signInActivity date fields' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{
  "id": "user-1",
  "signInActivity": {
    "lastSignInDateTime": "2026-08-01T00:00:00Z",
    "lastNonInteractiveSignInDateTime": "2026-08-05T00:00:00Z",
    "lastSuccessfulSignInDateTime": "2026-08-05T00:00:00Z"
  }
}
'@
        $entity = ConvertTo-EntraPostureUserSignInActivityEntity -RawUser $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.entityId | Should -Be 'user-1'
        $entity.entityType | Should -Be 'UserSignInActivity'
        $entity.properties.lastSignInDateTime | Should -Be '2026-08-01T00:00:00Z'
        $entity.properties.lastNonInteractiveSignInDateTime | Should -Be '2026-08-05T00:00:00Z'
        $entity.properties.lastSuccessfulSignInDateTime | Should -Be '2026-08-05T00:00:00Z'
    }

    It 'leaves every date field null when signInActivity is absent (never signed in)' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "id": "user-2" }'
        $entity = ConvertTo-EntraPostureUserSignInActivityEntity -RawUser $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.lastSuccessfulSignInDateTime | Should -Be $null
    }

    It 'throws when the raw record has no id' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "signInActivity": {} }'
        { ConvertTo-EntraPostureUserSignInActivityEntity -RawUser $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z' } | Should -Throw '*no id*'
    }
}
