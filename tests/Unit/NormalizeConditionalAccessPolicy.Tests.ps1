#Requires -Version 7.4
#Requires -Modules Pester

<#
    Phase 8: expansion of ConvertTo-EntraPostureConditionalAccessPolicyEntity from Phase 5's
    minimal (state/displayName/dates-only) stub to the full condition/grant-control/session-
    control object graph the CA simulation engine needs. Field shapes confirmed directly against
    current Microsoft Graph v1.0 resource documentation -- see the normalizer's own DESCRIPTION
    for citation dates and the explicit list of deliberately-not-captured fields.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Validation/StrictJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/CanonicalJson.ps1')
    . (Join-Path $script:RepoRoot 'src/Normalization/NormalizeConditionalAccessPolicy.ps1')

    function script:ConvertTo-TestOrderedDictionary {
        param([Parameter(Mandatory)][string]$Json)
        return ConvertFrom-EntraPostureJson -Json $Json
    }
}

Describe 'ConvertTo-EntraPostureConditionalAccessPolicyEntity' {
    It 'maps a fully-populated policy''s conditions, grantControls, and sessionControls correctly' {
        $raw = ConvertTo-TestOrderedDictionary -Json @'
{
  "id": "policy-1", "displayName": "Require MFA for admins", "state": "enabled",
  "createdDateTime": "2025-01-01T00:00:00Z", "modifiedDateTime": "2025-06-01T00:00:00Z",
  "conditions": {
    "clientAppTypes": ["all"], "signInRiskLevels": ["high"], "userRiskLevels": ["medium"],
    "servicePrincipalRiskLevels": [], "insiderRiskLevels": null,
    "users": {
      "includeUsers": ["All"], "excludeUsers": ["break-glass-1"],
      "includeGroups": [], "excludeGroups": ["grp-exempt"],
      "includeRoles": ["role-ga"], "excludeRoles": [],
      "includeGuestsOrExternalUsers": { "guestOrExternalUserTypes": "b2bCollaborationGuest,b2bCollaborationMember" },
      "excludeGuestsOrExternalUsers": null
    },
    "applications": { "includeApplications": ["All"], "excludeApplications": [], "includeUserActions": [], "includeAuthenticationContextClassReferences": [] },
    "platforms": { "includePlatforms": ["all"], "excludePlatforms": ["iOS"] },
    "locations": { "includeLocations": ["All"], "excludeLocations": ["AllTrusted"] },
    "devices": { "deviceFilter": { "mode": "exclude", "rule": "device.trustType -eq \"AzureAD\"" } },
    "clientApplications": null,
    "authenticationFlows": { "transferMethods": "deviceCodeFlow" }
  },
  "grantControls": { "operator": "AND", "builtInControls": ["mfa", "compliantDevice"], "customAuthenticationFactors": [], "termsOfUse": [], "authenticationStrength": { "id": "strength-1" } },
  "sessionControls": {
    "signInFrequency": { "isEnabled": true, "value": 4, "type": "hours", "frequencyInterval": "timeBased" },
    "persistentBrowser": { "isEnabled": true, "mode": "never" },
    "applicationEnforcedRestrictions": { "isEnabled": false },
    "cloudAppSecurity": { "isEnabled": false, "cloudAppSecurityType": null },
    "disableResilienceDefaults": false
  }
}
'@
        $entity = ConvertTo-EntraPostureConditionalAccessPolicyEntity -RawPolicy $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint '/v1.0/identity/conditionalAccess/policies' -CollectedAt '2026-01-01T00:00:00Z'

        $entity.entityId | Should -Be 'policy-1'
        $entity.properties.state | Should -Be 'enabled'

        $entity.properties.conditions.signInRiskLevels | Should -Be @('high')
        $entity.properties.conditions.users.includeUsers | Should -Be @('All')
        $entity.properties.conditions.users.excludeUsers | Should -Be @('break-glass-1')
        $entity.properties.conditions.users.excludeGroups | Should -Be @('grp-exempt')
        $entity.properties.conditions.users.includeGuestOrExternalUserTypes | Should -Be @('b2bCollaborationGuest', 'b2bCollaborationMember')
        $entity.properties.conditions.applications.includeApplications | Should -Be @('All')
        $entity.properties.conditions.platforms.excludePlatforms | Should -Be @('iOS')
        $entity.properties.conditions.locations.excludeLocations | Should -Be @('AllTrusted')
        $entity.properties.conditions.devices.deviceFilterMode | Should -Be 'exclude'
        $entity.properties.conditions.devices.deviceFilterRule | Should -Be 'device.trustType -eq "AzureAD"'
        $entity.properties.conditions.authenticationFlowTransferMethods | Should -Be 'deviceCodeFlow'

        $entity.properties.grantControls.operator | Should -Be 'AND'
        $entity.properties.grantControls.builtInControls | Should -Be @('mfa', 'compliantDevice')
        $entity.properties.grantControls.authenticationStrengthId | Should -Be 'strength-1'

        $entity.properties.sessionControls.signInFrequencyValue | Should -Be 4
        $entity.properties.sessionControls.persistentBrowserMode | Should -Be 'never'
        $entity.properties.sessionControls.disableResilienceDefaults | Should -Be $false
    }

    It 'defaults every array field to an empty array (not null) when conditions is entirely absent' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{"id":"policy-2","displayName":"Bare policy","state":"disabled"}'
        $entity = ConvertTo-EntraPostureConditionalAccessPolicyEntity -RawPolicy $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint '/v1.0/identity/conditionalAccess/policies' -CollectedAt '2026-01-01T00:00:00Z'

        # Not `$x | Should -BeOfType [object[]]` -- piping an empty array sends zero objects
        # down the pipeline (the same array-unwrapping class this project has hit repeatedly in
        # module code, this time in test code), which Should reports as receiving $null rather
        # than an empty array. @() wrap + .Count is the correct pattern, used everywhere else in
        # this project's own test suite.
        ($null -ne $entity.properties.conditions.clientAppTypes) | Should -BeTrue
        @($entity.properties.conditions.clientAppTypes).Count | Should -Be 0
        @($entity.properties.conditions.users.includeUsers).Count | Should -Be 0
        @($entity.properties.grantControls.builtInControls).Count | Should -Be 0
        $entity.properties.grantControls.operator | Should -Be $null
        $entity.properties.grantControls.authenticationStrengthId | Should -Be $null
    }

    It 'handles a report-only policy state correctly' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{"id":"policy-3","displayName":"Report only","state":"enabledForReportingButNotEnforced"}'
        $entity = ConvertTo-EntraPostureConditionalAccessPolicyEntity -RawPolicy $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint '/v1.0/identity/conditionalAccess/policies' -CollectedAt '2026-01-01T00:00:00Z'
        $entity.properties.state | Should -Be 'enabledForReportingButNotEnforced'
    }

    It 'throws when the raw record has no id' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{"displayName":"No id"}'
        { ConvertTo-EntraPostureConditionalAccessPolicyEntity -RawPolicy $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint '/v1.0/identity/conditionalAccess/policies' -CollectedAt '2026-01-01T00:00:00Z' } |
            Should -Throw '*no id*'
    }

    It 'round-trips through canonical JSON serialization without error' {
        $raw = ConvertTo-TestOrderedDictionary -Json '{"id":"policy-4","displayName":"Round trip","state":"enabled","conditions":{"clientAppTypes":["browser"]},"grantControls":{"operator":"OR","builtInControls":["mfa"]}}'
        $entity = ConvertTo-EntraPostureConditionalAccessPolicyEntity -RawPolicy $raw -TenantScope 't1' -CollectorVersion '0.1.0' -SourceEndpoint '/v1.0/identity/conditionalAccess/policies' -CollectedAt '2026-01-01T00:00:00Z'
        { ConvertTo-EntraPostureCanonicalJson -InputObject $entity } | Should -Not -Throw
    }
}
