#Requires -Version 7.4
#Requires -Modules Pester

<#
    Update-EntraPostureKnownAbusedAppList never talks to real github.com in tests -- a local
    HttpListener mock server stands in for api.github.com/raw.githubusercontent.com via
    -ApiBaseUrlOverride/-RawBaseUrlOverride, the same discipline every other network-touching
    command in this project's test suite already follows (never a real external call in CI).
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    foreach ($relPath in @(
        'src/Common/CanonicalJson.ps1', 'src/Validation/StrictJson.ps1',
        'src/Common/ParseRogueAppsToml.ps1', 'src/Common/KnownAbusedAppListPath.ps1',
        'src/Authentication/LoopbackListener.ps1',
        'src/Public/Update-EntraPostureKnownAbusedAppList.ps1'
    )) {
        . (Join-Path $script:RepoRoot $relPath)
    }

    $script:SampleTomlV1 = @'
[[apps]]
appId = "e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd"
appDisplayName = "eM Client"
appOwnerOrganizationId = "146ecd75-4414-4ecf-ba6d-ea611895da8c"
appPublisherName = "eM Client s.r.o."
appPublisherId = "5365206"
description = "A robust email client."
tags = ["BEC"]
references = []
mitreTTP = []
contributors = ["Huntress Research Team"]
dateAdded = "2024-08-05"
'@

    $script:SampleTomlV2 = @'
[[apps]]
appId = "e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd"
appDisplayName = "eM Client"
appOwnerOrganizationId = "146ecd75-4414-4ecf-ba6d-ea611895da8c"
appPublisherName = "eM Client s.r.o."
appPublisherId = "5365206"
description = "A robust email client."
tags = ["BEC"]
references = []
mitreTTP = []
contributors = ["Huntress Research Team"]
dateAdded = "2024-08-05"

[[apps]]
appId = "ff8d92dc-3d82-41d6-bcbd-b9174d163620"
appDisplayName = "PerfectData Software"
appOwnerOrganizationId = "unknown"
appPublisherName = "unknown"
appPublisherId = "unknown"
description = "Exports mailboxes."
tags = ["exfiltration"]
references = []
mitreTTP = []
contributors = ["Syne0"]
dateAdded = "2024-08-14"
'@

    $script:MockServerScript = {
        param($Listener, $ResponseMap)
        while ($Listener.IsListening) {
            try { $context = $Listener.GetContext() } catch { break }
            $path = $context.Request.Url.AbsolutePath
            if ($ResponseMap.ContainsKey($path)) {
                $entry = $ResponseMap[$path]
                $context.Response.StatusCode = 200
                $context.Response.ContentType = $entry.ContentType
                $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$entry.Body)
            } else {
                $context.Response.StatusCode = 404
                $context.Response.ContentType = 'application/json'
                $bytes = [System.Text.Encoding]::UTF8.GetBytes('{"message":"not found: ' + $path + '"}')
            }
            $context.Response.ContentLength64 = $bytes.Length
            $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $context.Response.OutputStream.Close()
        }
    }

    function script:Start-KnownAbusedAppMockServer {
        param([hashtable]$ResponseMap)
        $port = Get-EntraPostureAvailableLoopbackPort
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add("http://127.0.0.1:$port/")
        $listener.Start()
        $syncMap = [System.Collections.Hashtable]::Synchronized($ResponseMap)
        $ps = [powershell]::Create()
        $ps.AddScript($script:MockServerScript).AddArgument($listener).AddArgument($syncMap) | Out-Null
        $asyncResult = $ps.BeginInvoke()
        return [ordered]@{ Listener = $listener; PowerShell = $ps; AsyncResult = $asyncResult; BaseUrl = "http://127.0.0.1:$port" }
    }

    function script:Stop-KnownAbusedAppMockServer {
        param($Server)
        if ($Server.Listener.IsListening) { $Server.Listener.Stop() }
        $Server.Listener.Close()
        try { $Server.PowerShell.EndInvoke($Server.AsyncResult) } catch { }
        $Server.PowerShell.Dispose()
    }

    function script:New-KnownAbusedAppResponseMap {
        param([string]$CommitSha = 'abc123', [string]$CommitDate = '2026-04-07T14:45:48Z', [string]$RawToml = $script:SampleTomlV1)
        return @{
            '/repos/huntresslabs/rogueapps/commits' = @{
                ContentType = 'application/json'
                Body = "[{`"sha`":`"$CommitSha`",`"commit`":{`"committer`":{`"date`":`"$CommitDate`"}}}]"
            }
            "/huntresslabs/rogueapps/$CommitSha/data/rogueapps.toml" = @{
                ContentType = 'text/plain'
                Body = $RawToml
            }
        }
    }
}

Describe 'Update-EntraPostureKnownAbusedAppList' {
    It 'reports IsStale=true with no local commit when no local file exists, without writing anything' {
        $server = Start-KnownAbusedAppMockServer -ResponseMap (New-KnownAbusedAppResponseMap -CommitSha 'commit-1')
        try {
            $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "known-abused-$([guid]::NewGuid()).toml"
            $result = Update-EntraPostureKnownAbusedAppList -Path $tempPath -ApiBaseUrlOverride $server.BaseUrl -RawBaseUrlOverride $server.BaseUrl

            $result.LocalCommitSha | Should -BeNullOrEmpty
            $result.RemoteCommitSha | Should -Be 'commit-1'
            $result.IsStale | Should -BeTrue
            $result.Saved | Should -BeFalse
            $result.Preview | Should -BeNullOrEmpty
            Test-Path -LiteralPath $tempPath | Should -BeFalse
        } finally {
            Stop-KnownAbusedAppMockServer -Server $server
        }
    }

    It 'reports IsStale=false when the local sidecar already records the latest remote commit' {
        $server = Start-KnownAbusedAppMockServer -ResponseMap (New-KnownAbusedAppResponseMap -CommitSha 'commit-2')
        try {
            $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "known-abused-$([guid]::NewGuid()).toml"
            $metaPath = [System.IO.Path]::ChangeExtension($tempPath, '.meta.json')
            [System.IO.File]::WriteAllText($metaPath, '{"commitSha":"commit-2"}', [System.Text.UTF8Encoding]::new($false))

            $result = Update-EntraPostureKnownAbusedAppList -Path $tempPath -ApiBaseUrlOverride $server.BaseUrl -RawBaseUrlOverride $server.BaseUrl
            $result.LocalCommitSha | Should -Be 'commit-2'
            $result.IsStale | Should -BeFalse
        } finally {
            Stop-KnownAbusedAppMockServer -Server $server
            Remove-Item -LiteralPath $metaPath -ErrorAction SilentlyContinue
        }
    }

    It '-Fetch previews the app count and diffs against an existing local copy without writing' {
        $server = Start-KnownAbusedAppMockServer -ResponseMap (New-KnownAbusedAppResponseMap -CommitSha 'commit-3' -RawToml $script:SampleTomlV2)
        try {
            $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "known-abused-$([guid]::NewGuid()).toml"
            [System.IO.File]::WriteAllText($tempPath, $script:SampleTomlV1, [System.Text.UTF8Encoding]::new($false))
            $originalContent = Get-Content -LiteralPath $tempPath -Raw

            $result = Update-EntraPostureKnownAbusedAppList -Path $tempPath -Fetch -ApiBaseUrlOverride $server.BaseUrl -RawBaseUrlOverride $server.BaseUrl

            $result.Preview.AppCount | Should -Be 2
            $result.Preview.AddedAppIds | Should -Be @('ff8d92dc-3d82-41d6-bcbd-b9174d163620')
            $result.Preview.RemovedAppIds.Count | Should -Be 0
            $result.Saved | Should -BeFalse
            (Get-Content -LiteralPath $tempPath -Raw) | Should -Be $originalContent
        } finally {
            Stop-KnownAbusedAppMockServer -Server $server
            Remove-Item -LiteralPath $tempPath -ErrorAction SilentlyContinue
        }
    }

    It '-Fetch -Save writes the fetched TOML and a sidecar metadata file with the correct fields' {
        $server = Start-KnownAbusedAppMockServer -ResponseMap (New-KnownAbusedAppResponseMap -CommitSha 'commit-4' -CommitDate '2026-05-01T00:00:00Z' -RawToml $script:SampleTomlV1)
        try {
            $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "known-abused-$([guid]::NewGuid()).toml"
            $metaPath = [System.IO.Path]::ChangeExtension($tempPath, '.meta.json')

            $result = Update-EntraPostureKnownAbusedAppList -Path $tempPath -Fetch -Save -Confirm:$false -ApiBaseUrlOverride $server.BaseUrl -RawBaseUrlOverride $server.BaseUrl

            $result.Saved | Should -BeTrue
            Test-Path -LiteralPath $tempPath | Should -BeTrue
            Test-Path -LiteralPath $metaPath | Should -BeTrue

            (Get-Content -LiteralPath $tempPath -Raw).Trim() | Should -Be $script:SampleTomlV1.Trim()

            $meta = ConvertFrom-EntraPostureJson -Json (Get-Content -LiteralPath $metaPath -Raw)
            $meta.commitSha | Should -Be 'commit-4'
            $meta.commitDateUtc | Should -Be '2026-05-01T00:00:00Z'
            $meta.appCount | Should -Be 1
            $meta.disclaimer | Should -Match 'not a confirmed-malicious list'
        } finally {
            Stop-KnownAbusedAppMockServer -Server $server
            Remove-Item -LiteralPath $tempPath -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $metaPath -ErrorAction SilentlyContinue
        }
    }

    It '-Fetch without -Save never writes to disk even when a local file already exists' {
        $server = Start-KnownAbusedAppMockServer -ResponseMap (New-KnownAbusedAppResponseMap -CommitSha 'commit-5' -RawToml $script:SampleTomlV2)
        try {
            $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "known-abused-$([guid]::NewGuid()).toml"
            [System.IO.File]::WriteAllText($tempPath, $script:SampleTomlV1, [System.Text.UTF8Encoding]::new($false))

            Update-EntraPostureKnownAbusedAppList -Path $tempPath -Fetch -ApiBaseUrlOverride $server.BaseUrl -RawBaseUrlOverride $server.BaseUrl | Out-Null

            (Get-Content -LiteralPath $tempPath -Raw).Trim() | Should -Be $script:SampleTomlV1.Trim()
        } finally {
            Stop-KnownAbusedAppMockServer -Server $server
            Remove-Item -LiteralPath $tempPath -ErrorAction SilentlyContinue
        }
    }

    It 'warns and ignores -Save when passed without -Fetch' {
        $server = Start-KnownAbusedAppMockServer -ResponseMap (New-KnownAbusedAppResponseMap -CommitSha 'commit-6')
        try {
            $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "known-abused-$([guid]::NewGuid()).toml"
            $result = Update-EntraPostureKnownAbusedAppList -Path $tempPath -Save -Confirm:$false -ApiBaseUrlOverride $server.BaseUrl -RawBaseUrlOverride $server.BaseUrl -WarningAction SilentlyContinue
            $result.Saved | Should -BeFalse
            Test-Path -LiteralPath $tempPath | Should -BeFalse
        } finally {
            Stop-KnownAbusedAppMockServer -Server $server
        }
    }

    It 'throws a clear error when the commits API returns no commit for the path' {
        $server = Start-KnownAbusedAppMockServer -ResponseMap @{
            '/repos/huntresslabs/rogueapps/commits' = @{ ContentType = 'application/json'; Body = '[]' }
        }
        try {
            $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "known-abused-$([guid]::NewGuid()).toml"
            { Update-EntraPostureKnownAbusedAppList -Path $tempPath -ApiBaseUrlOverride $server.BaseUrl -RawBaseUrlOverride $server.BaseUrl } | Should -Throw '*no commit*'
        } finally {
            Stop-KnownAbusedAppMockServer -Server $server
        }
    }
}
