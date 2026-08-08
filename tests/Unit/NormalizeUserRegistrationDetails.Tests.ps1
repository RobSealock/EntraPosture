#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 2, the 109-row backlog continuation (batch 12, 2026-08-08): ConvertTo-
    EntraPostureUserRegistrationDetailsEntity, field shapes confirmed directly against the live
    "List userRegistrationDetails" and "userRegistrationDetails resource type" Graph reference
    pages (re-fetched 2026-08-08) -- see the normalizer's own DESCRIPTION.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeUserRegistrationDetails.ps1')

    function script:ConvertTo-TestOrderedDictionary {
        param([Parameter(Mandatory)][string]$Json)
        return ConvertFrom-EntraPostureJson -Json $Json
    }
}

Describe 'ConvertTo-EntraPostureUserRegistrationDetailsEntity' {
    It 'extracts isMfaRegistered and the other registration-state fields' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{
  "id": "86462606-fde0-4fc4-9e0c-a20eb73e54c6", "userPrincipalName": "AlexW@Contoso.com",
  "userDisplayName": "Alex Wilber", "isAdmin": false, "isSsprRegistered": false,
  "isSsprEnabled": false, "isSsprCapable": false, "isMfaRegistered": true, "isMfaCapable": true,
  "isPasswordlessCapable": false, "methodsRegistered": ["microsoftAuthenticatorPush", "softwareOneTimePasscode"],
  "userType": "member"
}
'@
        $entity = ConvertTo-EntraPostureUserRegistrationDetailsEntity -RawUserRegistrationDetail $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.entityId | Should -Be '86462606-fde0-4fc4-9e0c-a20eb73e54c6'
        $entity.entityType | Should -Be 'UserRegistrationDetails'
        $entity.displayName | Should -Be 'Alex Wilber'
        $entity.properties.isMfaRegistered | Should -Be $true
        $entity.properties.isAdmin | Should -Be $false
        @($entity.properties.methodsRegistered) | Should -Be @('microsoftAuthenticatorPush', 'softwareOneTimePasscode')
    }

    It 'defaults methodsRegistered to an empty array and isMfaRegistered to null when absent' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "id": "u2" }'
        $entity = ConvertTo-EntraPostureUserRegistrationDetailsEntity -RawUserRegistrationDetail $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.isMfaRegistered | Should -Be $null
        @($entity.properties.methodsRegistered).Count | Should -Be 0
    }

    It 'throws when the raw record has no id' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "userDisplayName": "no id" }'
        { ConvertTo-EntraPostureUserRegistrationDetailsEntity -RawUserRegistrationDetail $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z' } | Should -Throw '*no id*'
    }
}
