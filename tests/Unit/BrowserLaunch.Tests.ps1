#Requires -Version 7.4
#Requires -Modules Pester

<#
    Added while answering a live-tenant connection question: the user wanted the delegated
    interactive sign-in to open in a specific browser's private/incognito window rather than
    the OS default handler's normal (possibly already-signed-in) profile. Covers the
    executable-resolution and argument-construction logic directly -- actually launching a real
    browser process is left untested here (there's nothing to assert against without spawning a
    real GUI browser in CI), matching how Start-EntraPostureAuthBrowser's own fallback path
    (-Browser omitted, plain Start-Process) was already implicitly exercised by every existing
    delegated-auth test before this capability existed.
#>

BeforeAll {
    $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
    . (Join-Path $script:RepoRoot 'src/Authentication/BrowserLaunch.ps1')

    function script:New-TestExecutable {
        param([string]$Name)
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "browser-launch-test-$([guid]::NewGuid())"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $path = Join-Path $dir $Name
        Set-Content -LiteralPath $path -Value '#!/bin/sh'
        return $path
    }
}

Describe 'Get-EntraPostureBrowserExecutablePath' {
    It 'returns the first candidate path that actually exists' {
        $real = New-TestExecutable -Name 'edge-fake'
        $result = Get-EntraPostureBrowserExecutablePath -Browser 'Edge' -CandidatePathsOverride @('/nonexistent/path/msedge', $real)
        $result | Should -Be (Resolve-Path -LiteralPath $real).Path
    }

    It 'throws, naming every path tried, when none of the candidates exist' {
        { Get-EntraPostureBrowserExecutablePath -Browser 'Chrome' -CandidatePathsOverride @('/nonexistent/a', '/nonexistent/b') } |
            Should -Throw '*Chrome*/nonexistent/a*/nonexistent/b*'
    }
}

Describe 'Start-EntraPostureAuthBrowser parameter validation' {
    It 'throws when -PrivateBrowsing is supplied without -Browser' {
        { Start-EntraPostureAuthBrowser -Url 'https://example.invalid/auth' -PrivateBrowsing } |
            Should -Throw '*-PrivateBrowsing requires -Browser*'
    }

    It 'throws Get-EntraPostureBrowserExecutablePath''s own error when -Browser is requested but not installed, rather than silently falling back' {
        { Start-EntraPostureAuthBrowser -Url 'https://example.invalid/auth' -Browser 'Firefox' -CandidatePathsOverride @('/nonexistent/firefox') } |
            Should -Throw '*Firefox*/nonexistent/firefox*'
    }
}

Describe 'Private-window flag selection' {
    BeforeAll {
        # Exercises the real launch path (no -Browser -> plain Start-Process on the URL) by
        # substituting a fake "browser" that just writes its received arguments to a file, so the
        # exact flag/URL ordering Start-EntraPostureAuthBrowser constructs can be asserted on
        # without opening a real browser window.
        function script:New-ArgCapturingScript {
            $dir = Join-Path ([System.IO.Path]::GetTempPath()) "browser-launch-argcap-$([guid]::NewGuid())"
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $capturePath = Join-Path $dir 'captured-args.txt'
            $scriptPath = Join-Path $dir 'fake-browser.sh'
            Set-Content -LiteralPath $scriptPath -Value "#!/bin/sh`necho `"`$@`" > `"$capturePath`"`n"
            chmod +x $scriptPath
            return [ordered]@{ ScriptPath = $scriptPath; CapturePath = $capturePath }
        }

        function script:Wait-ForCaptureFile {
            param([string]$Path, [int]$TimeoutMilliseconds = 3000)
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            while ($stopwatch.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
                if (Test-Path -LiteralPath $Path -PathType Leaf) { return }
                Start-Sleep -Milliseconds 50
            }
            throw "Wait-ForCaptureFile: '$Path' did not appear within $TimeoutMilliseconds ms."
        }
    }

    It 'passes --inprivate before the URL for Edge private browsing' {
        if ($IsWindows) { Set-ItResult -Skipped -Because 'Start-Process argument capture via a shell script is a POSIX-only test technique.'; return }
        $fake = New-ArgCapturingScript
        Start-EntraPostureAuthBrowser -Url 'https://example.invalid/auth?x=1' -Browser 'Edge' -PrivateBrowsing -CandidatePathsOverride @($fake.ScriptPath)
        Wait-ForCaptureFile -Path $fake.CapturePath
        (Get-Content -LiteralPath $fake.CapturePath -Raw).Trim() | Should -Be '--inprivate https://example.invalid/auth?x=1'
    }

    It 'passes --incognito before the URL for Chrome private browsing' {
        if ($IsWindows) { Set-ItResult -Skipped -Because 'Start-Process argument capture via a shell script is a POSIX-only test technique.'; return }
        $fake = New-ArgCapturingScript
        Start-EntraPostureAuthBrowser -Url 'https://example.invalid/auth' -Browser 'Chrome' -PrivateBrowsing -CandidatePathsOverride @($fake.ScriptPath)
        Wait-ForCaptureFile -Path $fake.CapturePath
        (Get-Content -LiteralPath $fake.CapturePath -Raw).Trim() | Should -Be '--incognito https://example.invalid/auth'
    }

    It 'passes -private-window before the URL for Firefox private browsing' {
        if ($IsWindows) { Set-ItResult -Skipped -Because 'Start-Process argument capture via a shell script is a POSIX-only test technique.'; return }
        $fake = New-ArgCapturingScript
        Start-EntraPostureAuthBrowser -Url 'https://example.invalid/auth' -Browser 'Firefox' -PrivateBrowsing -CandidatePathsOverride @($fake.ScriptPath)
        Wait-ForCaptureFile -Path $fake.CapturePath
        (Get-Content -LiteralPath $fake.CapturePath -Raw).Trim() | Should -Be '-private-window https://example.invalid/auth'
    }

    It 'launches without a private-window flag when -Browser is given without -PrivateBrowsing' {
        if ($IsWindows) { Set-ItResult -Skipped -Because 'Start-Process argument capture via a shell script is a POSIX-only test technique.'; return }
        $fake = New-ArgCapturingScript
        Start-EntraPostureAuthBrowser -Url 'https://example.invalid/auth' -Browser 'Chrome' -CandidatePathsOverride @($fake.ScriptPath)
        Wait-ForCaptureFile -Path $fake.CapturePath
        (Get-Content -LiteralPath $fake.CapturePath -Raw).Trim() | Should -Be 'https://example.invalid/auth'
    }
}
