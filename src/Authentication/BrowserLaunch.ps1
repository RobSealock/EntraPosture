#Requires -Version 7.4

function Get-EntraPostureBrowserExecutablePath {
    <#
        .SYNOPSIS
        Resolves an installed browser's executable path for a named browser, across
        Windows/macOS/Linux.

        .DESCRIPTION
        Not exported. Used only by Start-EntraPostureAuthBrowser to launch a specific browser
        in a private/incognito window for delegated interactive sign-in, when a caller wants
        isolation from their normal browser profile's existing SSO session rather than relying
        on Microsoft's own prompt=select_account/login OAuth parameters (a lighter-weight
        alternative this project deliberately did not choose here, per the explicit choice made
        when this capability was added -- see Start-EntraPostureAuthBrowser's own comment).

        Tries a short list of well-known install locations per platform (Windows: both
        Program Files and Program Files (x86); macOS: /Applications; Linux: resolved via PATH,
        since Linux distributions don't have a single conventional install directory the way
        Windows/macOS do) and returns the first that exists. Throws, naming every path tried,
        rather than silently falling back to a different browser or the OS default -- a caller
        who explicitly asked for Edge and doesn't have it installed should see a clear error, not
        a silent substitution.

        .PARAMETER Browser
        .PARAMETER CandidatePathsOverride
        Test-only: replaces the platform-derived candidate list entirely, so this function's
        first-match/throw logic can be tested without depending on which real browsers happen to
        be installed on the machine running the test suite. Production callers must never pass
        this.

        .OUTPUTS
        Absolute path (or resolved PATH entry) to the browser executable.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('Edge', 'Chrome', 'Firefox')]
        [string]$Browser,

        [Parameter()]
        [string[]]$CandidatePathsOverride
    )

    if ($CandidatePathsOverride) {
        foreach ($path in $CandidatePathsOverride) {
            if (Test-Path -LiteralPath $path -PathType Leaf) { return (Resolve-Path -LiteralPath $path).Path }
        }
        throw "Get-EntraPostureBrowserExecutablePath: could not find a '$Browser' executable. Tried: $($CandidatePathsOverride -join ', ')."
    }

    $candidatePaths = @()
    $isLinuxPathSearch = $false

    if ($IsWindows) {
        $candidatePaths = switch ($Browser) {
            'Edge'    { @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe") }
            'Chrome'  { @("${env:ProgramFiles}\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") }
            'Firefox' { @("${env:ProgramFiles}\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") }
        }
    } elseif ($IsMacOS) {
        $candidatePaths = switch ($Browser) {
            'Edge'    { @('/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge') }
            'Chrome'  { @('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome') }
            'Firefox' { @('/Applications/Firefox.app/Contents/MacOS/firefox') }
        }
    } elseif ($IsLinux) {
        $isLinuxPathSearch = $true
        $candidatePaths = switch ($Browser) {
            'Edge'    { @('microsoft-edge', 'microsoft-edge-stable') }
            'Chrome'  { @('google-chrome', 'google-chrome-stable') }
            'Firefox' { @('firefox') }
        }
    } else {
        throw 'Get-EntraPostureBrowserExecutablePath: unrecognized platform (none of $IsWindows/$IsMacOS/$IsLinux is true).'
    }

    foreach ($path in $candidatePaths) {
        if ($isLinuxPathSearch) {
            $resolved = Get-Command -Name $path -ErrorAction SilentlyContinue
            if ($resolved) { return $resolved.Source }
        } elseif (Test-Path -LiteralPath $path -PathType Leaf) {
            return $path
        }
    }

    throw "Get-EntraPostureBrowserExecutablePath: could not find a '$Browser' executable. Tried: $($candidatePaths -join ', ')."
}

function Start-EntraPostureAuthBrowser {
    <#
        .SYNOPSIS
        Opens a URL for delegated interactive sign-in, optionally in a specific browser's
        private/incognito window.

        .DESCRIPTION
        Default behavior (no -Browser) is unchanged from before this capability existed:
        Start-Process -FilePath $Url, which hands the URL to the OS-registered default handler
        (default browser, normal profile, existing SSO session included).

        -Browser plus -PrivateBrowsing launches that specific browser directly with its
        private-window command-line flag (Edge --inprivate, Chrome --incognito, Firefox
        -private-window), so the sign-in happens in a browser profile with no existing
        Microsoft session/cookies -- useful when the caller's normal browser is already signed
        in as a different account and they want to authenticate as someone else without first
        signing out of their day-to-day session. -Browser without -PrivateBrowsing launches that
        specific browser normally (still useful for choosing a browser other than the OS
        default, without the incognito requirement).

        Deliberately does not use Microsoft's own prompt=select_account/login OAuth parameters
        as an alternative to this -- both were considered; incognito/private-window launch was
        the explicit choice made when this capability was requested, because it isolates the
        entire browser profile (cookies, autofill, extensions) rather than only forcing an
        account picker within the existing session.

        -PrivateBrowsing without -Browser is a caller error (there is no single "OS default
        browser's private-window flag" this function can guess) -- throws immediately rather
        than silently falling back to a normal window.

        .PARAMETER Url
        .PARAMETER Browser
        .PARAMETER PrivateBrowsing
        .PARAMETER CandidatePathsOverride
        Test-only passthrough to Get-EntraPostureBrowserExecutablePath.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Launches a local browser process for the user to interact with -- the same category of local, user-facing action as Start-Process itself, which this function wraps; nothing here is a state change -WhatIf/-Confirm would meaningfully guard.')]
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter()]
        [ValidateSet('Edge', 'Chrome', 'Firefox')]
        [string]$Browser,

        [Parameter()]
        [switch]$PrivateBrowsing,

        [Parameter()]
        [string[]]$CandidatePathsOverride
    )

    if ($PrivateBrowsing -and -not $Browser) {
        throw 'Start-EntraPostureAuthBrowser: -PrivateBrowsing requires -Browser (there is no single private-window flag for "whatever the OS default browser is").'
    }

    if (-not $Browser) {
        Start-Process -FilePath $Url | Out-Null
        return
    }

    $executablePath = Get-EntraPostureBrowserExecutablePath -Browser $Browser -CandidatePathsOverride $CandidatePathsOverride

    $arguments = [System.Collections.Generic.List[string]]::new()
    if ($PrivateBrowsing) {
        $privateFlag = switch ($Browser) {
            'Edge'    { '--inprivate' }
            'Chrome'  { '--incognito' }
            'Firefox' { '-private-window' }
        }
        $arguments.Add($privateFlag)
    }
    $arguments.Add($Url)

    Start-Process -FilePath $executablePath -ArgumentList $arguments.ToArray() | Out-Null
}
