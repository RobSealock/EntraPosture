#Requires -Version 7.4
#Requires -Modules Pester

<#
    Unit tests for ConvertFrom-EntraPostureRogueAppsToml (ENT-013 groundwork, ranked-order
    continuation) -- the bounded TOML-subset parser for huntresslabs/rogueapps' own
    data/rogueapps.toml shape. See that function's own DESCRIPTION for why this is a
    purpose-built subset parser, not a general TOML implementation.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Common/ParseRogueAppsToml.ps1')
    . (Join-Path $script:RepoRoot 'src/Common/KnownAbusedAppListPath.ps1')

    $script:SampleToml = @'
[[apps]]
appId = "e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd"
appDisplayName = "eM Client"
appOwnerOrganizationId = "146ecd75-4414-4ecf-ba6d-ea611895da8c"
appPublisherName = "eM Client s.r.o."
appPublisherId = "5365206"
description = "A robust email client, sometimes with an escaped \"quote\" inside."
tags = ["BEC", "email", "spam"]
references = [
  "https://www.emclient.com/",
  "https://example.com/second",
]
mitreTTP = []
contributors = ["Huntress Research Team", "lukesteward"]
dateAdded = "2024-08-05"

[[apps.permissions]]
resource = "Microsoft Graph"
permission = "EWS.AccessAsUser.All"
type = "Delegated"

[[apps.permissions]]
resource = "Microsoft Graph"
permission = "offline_access"
type = "Delegated"

[[apps]]
appId = "ff8d92dc-3d82-41d6-bcbd-b9174d163620"
appDisplayName = "PerfectData Software"
appOwnerOrganizationId = "unknown"
appPublisherName = "unknown"
appPublisherId = "unknown"
description = "Exports mailboxes."
tags = ["exfiltration"]
references = []
mitreTTP = ["T1567"]
contributors = ["Syne0"]
dateAdded = "2024-08-14"
'@
}

Describe 'ConvertFrom-EntraPostureRogueAppsToml' {
    It 'parses multiple [[apps]] blocks with scalar fields, single-line and multi-line arrays, and nested [[apps.permissions]]' {
        $apps = ConvertFrom-EntraPostureRogueAppsToml -RawToml $script:SampleToml
        $apps.Count | Should -Be 2

        $apps[0].appId | Should -Be 'e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd'
        $apps[0].appDisplayName | Should -Be 'eM Client'
        $apps[0].tags | Should -Be @('BEC', 'email', 'spam')
        $apps[0].references.Count | Should -Be 2
        $apps[0].references[0] | Should -Be 'https://www.emclient.com/'
        $apps[0].mitreTTP.Count | Should -Be 0
        $apps[0].description | Should -Match 'escaped "quote" inside'
        $apps[0].permissions.Count | Should -Be 2
        $apps[0].permissions[0].resource | Should -Be 'Microsoft Graph'
        $apps[0].permissions[0].permission | Should -Be 'EWS.AccessAsUser.All'
        $apps[0].permissions[1].permission | Should -Be 'offline_access'

        $apps[1].appId | Should -Be 'ff8d92dc-3d82-41d6-bcbd-b9174d163620'
        $apps[1].references.Count | Should -Be 0
        $apps[1].mitreTTP | Should -Be @('T1567')
        $apps[1].permissions.Count | Should -Be 0
    }

    It 'parses an empty document to zero apps' {
        $apps = ConvertFrom-EntraPostureRogueAppsToml -RawToml ''
        @($apps).Count | Should -Be 0
    }

    It 'throws on an [[apps]] block missing appId' {
        { ConvertFrom-EntraPostureRogueAppsToml -RawToml "[[apps]]`nappDisplayName = `"x`"" } | Should -Throw '*has no appId*'
    }

    It 'throws on [[apps.permissions]] before any [[apps]] block' {
        { ConvertFrom-EntraPostureRogueAppsToml -RawToml '[[apps.permissions]]' } | Should -Throw '*before any*'
    }

    It 'throws on an unrecognized key' {
        { ConvertFrom-EntraPostureRogueAppsToml -RawToml "[[apps]]`nappId = `"x`"`nbogusField = `"y`"" } | Should -Throw '*unrecognized key*'
    }

    It 'throws on an unterminated string' {
        { ConvertFrom-EntraPostureRogueAppsToml -RawToml "[[apps]]`nappId = `"unterminated" } | Should -Throw '*unterminated string*'
    }

    It 'throws on an unterminated array' {
        { ConvertFrom-EntraPostureRogueAppsToml -RawToml "[[apps]]`nappId = `"x`"`ntags = [`n  `"a`"" } | Should -Throw '*unterminated array*'
    }

    It 'throws on an unrecognized line shape' {
        { ConvertFrom-EntraPostureRogueAppsToml -RawToml "[[apps]]`nappId = `"x`"`nnotAnAssignment" } | Should -Throw '*unrecognized line*'
    }

    It 'parses the real vendored data/known-abused-apps.toml seed file without error' {
        $seedPath = Join-Path $script:RepoRoot 'data/known-abused-apps.toml'
        $raw = Get-Content -LiteralPath $seedPath -Raw
        $apps = ConvertFrom-EntraPostureRogueAppsToml -RawToml $raw
        $apps.Count | Should -BeGreaterThan 0
        foreach ($app in $apps) {
            [string]::IsNullOrWhiteSpace($app.appId) | Should -BeFalse
        }
    }
}

Describe 'Get-EntraPostureKnownAbusedAppListPath' {
    It 'resolves to a data/ directory containing known-abused-apps.toml as its file name' {
        $resolved = Get-EntraPostureKnownAbusedAppListPath
        $resolved.TomlPath | Should -Match 'known-abused-apps\.toml$'
        $resolved.MetaPath | Should -Match 'known-abused-apps\.meta\.json$'
        Split-Path -Path $resolved.TomlPath -Parent | Should -Be (Split-Path -Path $resolved.MetaPath -Parent)
    }
}
