#Requires -Version 7.4
#Requires -Modules Pester

<#
    VNext build order item 5 (authenticationStrength half): ConvertTo-EntraPostureAuthenticationStrengthPolicyEntity,
    field shapes confirmed directly against Microsoft Graph's authenticationStrengthPolicy resource
    documentation (re-fetched 2026-08-07) -- see the normalizer's own DESCRIPTION.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeAuthenticationStrengthPolicy.ps1')

    function script:ConvertTo-TestOrderedDictionary {
        param([Parameter(Mandatory)][string]$Json)
        return ConvertFrom-EntraPostureJson -Json $Json
    }
}

Describe 'ConvertTo-EntraPostureAuthenticationStrengthPolicyEntity' {
    It 'maps a built-in policy''s policyType, requirementsSatisfied, and allowedCombinations' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{
  "id": "00000000-0000-0000-0000-000000000004", "displayName": "Phishing resistant MFA",
  "description": "Phishing resistant, Passwordless methods for the strongest authentication",
  "createdDateTime": "2021-12-01T00:00:00Z", "modifiedDateTime": "2021-12-01T00:00:00Z",
  "policyType": "builtIn", "requirementsSatisfied": "mfa",
  "allowedCombinations": ["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"]
}
'@
        $entity = ConvertTo-EntraPostureAuthenticationStrengthPolicyEntity -RawPolicy $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.entityId | Should -Be '00000000-0000-0000-0000-000000000004'
        $entity.entityType | Should -Be 'AuthenticationStrengthPolicy'
        $entity.displayName | Should -Be 'Phishing resistant MFA'
        $entity.properties.policyType | Should -Be 'builtIn'
        $entity.properties.requirementsSatisfied | Should -Be 'mfa'
        @($entity.properties.allowedCombinations) | Should -Be @('windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor')
    }

    It 'maps a custom policy that does not satisfy MFA' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{
  "id": "custom-1", "displayName": "Single factor", "policyType": "custom",
  "requirementsSatisfied": "none", "allowedCombinations": ["password"]
}
'@
        $entity = ConvertTo-EntraPostureAuthenticationStrengthPolicyEntity -RawPolicy $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.policyType | Should -Be 'custom'
        $entity.properties.requirementsSatisfied | Should -Be 'none'
    }

    It 'throws when the raw record has no id' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{ "displayName": "no id" }'
        { ConvertTo-EntraPostureAuthenticationStrengthPolicyEntity -RawPolicy $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint 'x' -CollectedAt '2026-01-01T00:00:00Z' } | Should -Throw '*no id*'
    }
}
