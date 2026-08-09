#Requires -Version 7.4

function Update-EntraPostureKnownAbusedAppList {
    <#
        .SYNOPSIS
        Manages the local vendored copy of the `huntresslabs/rogueapps` known-abused-application
        dataset (ENT-013's own reference data) -- entirely separate from, and never called by,
        the core assessment pipeline.

        .DESCRIPTION
        This is the ONE deliberate exception to the guarantee stated in
        docs/SecurityAndStorage.md ("every network call this tool makes is either a Microsoft
        Graph/ARM API call you explicitly triggered, or the OAuth token endpoint during
        authentication") -- and it is an exception you must explicitly invoke; New-
        EntraPostureSnapshot/Invoke-EntraPosture never call this cmdlet or reach github.com
        themselves. It talks to api.github.com and raw.githubusercontent.com, never Microsoft
        Graph/ARM, and is never wired into the Test-EntraPosturePreflight/EndpointAllowlist
        machinery those calls go through -- a structurally different kind of call (anonymous,
        no OAuth token, a different host entirely), kept in this one isolated file so that
        distinction is obvious to a reader, not blurred into the tenant-evidence transport layer.

        Four modes, chosen by which switches are supplied:
        - No switches (default): calls the GitHub commits API for the single most recent commit
          touching data/rogueapps.toml on -Ref, compares its commit SHA against the local
          sidecar's own recorded SHA (if a local copy exists at all), and reports whether a newer
          remote version exists -- touches no local files either way. Always prints the raw file
          URL so you can download and place it yourself instead (data/rogueapps.toml at that
          commit, on https://github.com/huntresslabs/rogueapps).
        - `-Fetch`: additionally pulls the raw TOML content at that exact commit SHA (pinned, not
          a moving branch ref) and parses it with ConvertFrom-EntraPostureRogueAppsToml, then
          prints a preview: total app count, and (if a local copy already exists) which appIds
          were added/removed compared to it. Nothing is written to disk yet -- this is the
          "inspect before using" step.
        - `-Fetch -Save`: same as -Fetch, then writes the fetched TOML to the resolved local path
          and a sidecar `*.meta.json` (source URL, commit SHA, commit date, fetchedAt, app count).
          Gated by -Confirm/-WhatIf (SupportsShouldProcess) rather than a bespoke prompt, since
          nothing else in this module uses an interactive Read-Host-style flow and this is the
          first command that writes outside a snapshot's own RunRoot.
        - `-Path <file>`: use this file as both the read (for `default`/`-Fetch` diffing) and
          write (for `-Save`) target instead of the resolved default under data/ -- the fully
          manual path: copy a file you downloaded yourself into place and point this cmdlet at it
          if you'd rather never have this cmdlet touch the network at all.

        .PARAMETER Fetch
        .PARAMETER Save
        Requires -Fetch. Ignored (with a warning) if passed alone.

        .PARAMETER Path
        Overrides the default local TOML file location resolved by
        Get-EntraPostureKnownAbusedAppListPath. The sidecar metadata file is derived from this
        same path (same base name, .meta.json extension).

        .PARAMETER Ref
        Branch, tag, or commit to resolve the "latest commit" against. Defaults to 'main'.

        .PARAMETER ApiBaseUrlOverride
        .PARAMETER RawBaseUrlOverride
        Test-only. Default to the real api.github.com / raw.githubusercontent.com.

        .OUTPUTS
        Ordered dictionary: LocalPath, LocalCommitSha, RemoteCommitSha, RemoteCommitDateUtc,
        IsStale, ManualDownloadUrl, Preview (present only when -Fetch is supplied: AppCount,
        AddedAppIds, RemovedAppIds), Saved (bool).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter()]
        [switch]$Fetch,

        [Parameter()]
        [switch]$Save,

        [Parameter()]
        [string]$Path,

        [Parameter()]
        [string]$Ref = 'main',

        [Parameter()]
        [string]$ApiBaseUrlOverride = 'https://api.github.com',

        [Parameter()]
        [string]$RawBaseUrlOverride = 'https://raw.githubusercontent.com'
    )

    if ($Save -and -not $Fetch) {
        Write-Warning 'Update-EntraPostureKnownAbusedAppList: -Save has no effect without -Fetch (nothing new was fetched to save). Ignoring -Save.'
        $Save = $false
    }

    if ($Path) {
        $tomlPath = $Path
        $metaPath = [System.IO.Path]::ChangeExtension($Path, '.meta.json')
    } else {
        $resolved = Get-EntraPostureKnownAbusedAppListPath
        $tomlPath = $resolved.TomlPath
        $metaPath = $resolved.MetaPath
    }

    $disclaimer = 'This dataset (huntresslabs/rogueapps) documents applications OBSERVED IN ADVERSARIAL CONTEXTS, not a confirmed-malicious list -- presence does not confirm malicious intent. Any ENT-013 finding built from it must be reviewed manually before action is taken.'
    Write-Host "[i] $disclaimer"

    $localCommitSha = $null
    if (Test-Path -LiteralPath $metaPath -PathType Leaf) {
        try {
            $localMeta = ConvertFrom-EntraPostureJson -Json (Get-Content -LiteralPath $metaPath -Raw)
            $localCommitSha = $localMeta.commitSha
        } catch {
            Write-Warning "Update-EntraPostureKnownAbusedAppList: local sidecar '$metaPath' could not be read as JSON ($($_.Exception.Message)) -- treating as if no local copy exists."
        }
    }

    $commitsUrl = "$ApiBaseUrlOverride/repos/huntresslabs/rogueapps/commits?path=data/rogueapps.toml&sha=$Ref&per_page=1"
    try {
        # Invoke-WebRequest + ConvertFrom-EntraPostureJson, not Invoke-RestMethod's own built-in
        # JSON parsing -- confirmed directly (a real test failure, not merely suspected) that
        # Invoke-RestMethod silently auto-converts the ISO-8601-shaped commit date into a live
        # [DateTime] rendered in local culture, exactly the ConvertFrom-Json footgun StrictJson.ps1's
        # own ConvertFrom-EntraPostureJson (-DateKind String) exists to avoid everywhere else in
        # this project.
        $commitsRawResponse = Invoke-WebRequest -Uri $commitsUrl -Method GET -Headers @{ 'User-Agent' = 'EntraPosture'; 'Accept' = 'application/vnd.github+json' } -UseBasicParsing -ErrorAction Stop
    } catch {
        throw "Update-EntraPostureKnownAbusedAppList: GitHub commits API request failed ($($_.Exception.Message)). No local state was changed."
    }
    $commitsResponse = ConvertFrom-EntraPostureJson -Json $commitsRawResponse.Content
    $latestCommit = @($commitsResponse)[0]
    if (-not $latestCommit -or -not $latestCommit.sha) {
        throw "Update-EntraPostureKnownAbusedAppList: GitHub commits API returned no commit for data/rogueapps.toml on ref '$Ref'."
    }
    $remoteCommitSha = [string]$latestCommit.sha
    $remoteCommitDateUtc = [string]$latestCommit.commit.committer.date

    $isStale = ($null -eq $localCommitSha) -or ($localCommitSha -ne $remoteCommitSha)
    $manualDownloadUrl = "https://github.com/huntresslabs/rogueapps/blob/$remoteCommitSha/data/rogueapps.toml"
    $rawUrl = "$RawBaseUrlOverride/huntresslabs/rogueapps/$remoteCommitSha/data/rogueapps.toml"

    if ($isStale) {
        Write-Host "[i] Local copy is $(if ($localCommitSha) { "from commit $localCommitSha" } else { 'absent' }); remote is at commit $remoteCommitSha (committed $remoteCommitDateUtc)."
    } else {
        Write-Host "[+] Local copy already matches the latest remote commit ($remoteCommitSha)."
    }
    Write-Host "[i] Manual download: view at $manualDownloadUrl or fetch the raw file directly from $rawUrl, then re-run with -Path pointing at wherever you saved it."

    $result = [ordered]@{
        LocalPath            = $tomlPath
        LocalCommitSha       = $localCommitSha
        RemoteCommitSha      = $remoteCommitSha
        RemoteCommitDateUtc  = $remoteCommitDateUtc
        IsStale              = $isStale
        ManualDownloadUrl    = $manualDownloadUrl
        Preview              = $null
        Saved                = $false
    }

    if (-not $Fetch) {
        return $result
    }

    try {
        $rawToml = Invoke-RestMethod -Uri $rawUrl -Method GET -Headers @{ 'User-Agent' = 'EntraPosture' } -UseBasicParsing -ErrorAction Stop
    } catch {
        throw "Update-EntraPostureKnownAbusedAppList: fetching raw TOML content failed ($($_.Exception.Message)). No local state was changed."
    }
    $rawToml = [string]$rawToml

    $fetchedApps = ConvertFrom-EntraPostureRogueAppsToml -RawToml $rawToml
    $fetchedAppIds = @($fetchedApps | ForEach-Object { $_.appId })

    $existingAppIds = @()
    if (Test-Path -LiteralPath $tomlPath -PathType Leaf) {
        try {
            $existingApps = ConvertFrom-EntraPostureRogueAppsToml -RawToml (Get-Content -LiteralPath $tomlPath -Raw)
            $existingAppIds = @($existingApps | ForEach-Object { $_.appId })
        } catch {
            Write-Warning "Update-EntraPostureKnownAbusedAppList: existing local file at '$tomlPath' could not be parsed ($($_.Exception.Message)) -- diffing against an empty baseline."
        }
    }

    $addedAppIds = @($fetchedAppIds | Where-Object { $_ -notin $existingAppIds })
    $removedAppIds = @($existingAppIds | Where-Object { $_ -notin $fetchedAppIds })

    Write-Host "[i] Fetched $($fetchedApps.Count) app entries at commit $remoteCommitSha."
    if ($addedAppIds.Count -gt 0) { Write-Host "[i] $($addedAppIds.Count) new appId(s) not in the current local copy: $($addedAppIds -join ', ')" }
    if ($removedAppIds.Count -gt 0) { Write-Host "[i] $($removedAppIds.Count) appId(s) in the current local copy no longer present remotely: $($removedAppIds -join ', ')" }

    $result.Preview = [ordered]@{
        AppCount      = $fetchedApps.Count
        AddedAppIds   = $addedAppIds
        RemovedAppIds = $removedAppIds
    }

    if (-not $Save) {
        return $result
    }

    if ($PSCmdlet.ShouldProcess($tomlPath, "Save fetched rogueapps.toml (commit $remoteCommitSha, $($fetchedApps.Count) apps)")) {
        $targetDir = Split-Path -Path $tomlPath -Parent
        if ($targetDir -and -not (Test-Path -LiteralPath $targetDir -PathType Container)) {
            New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        }

        [System.IO.File]::WriteAllText($tomlPath, $rawToml, [System.Text.UTF8Encoding]::new($false))

        $metaRecord = [ordered]@{
            sourceUrl     = $manualDownloadUrl
            commitSha     = $remoteCommitSha
            commitDateUtc = $remoteCommitDateUtc
            fetchedAtUtc  = (Get-Date).ToUniversalTime().ToString('o')
            appCount      = $fetchedApps.Count
            disclaimer    = $disclaimer
        }
        [System.IO.File]::WriteAllText($metaPath, (ConvertTo-EntraPostureCanonicalJson -InputObject $metaRecord), [System.Text.UTF8Encoding]::new($false))

        Write-Host "[+] Saved $($fetchedApps.Count) app entries to $tomlPath (commit $remoteCommitSha)."
        $result.Saved = $true
    }

    return $result
}
